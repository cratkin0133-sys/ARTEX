package server

import (
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/Autumn-27/artex/egress"
	"github.com/Autumn-27/artex/traffic"
)

// putSettingsRequest is the body of PUT /api/settings. Every field is optional:
// null or omitted leaves that setting unchanged.
type putSettingsRequest struct {
	TrafficCapture      *bool `json:"traffic_capture"`
	AgentTrafficBinding *bool `json:"agent_traffic_binding"`
	LLMRecord           *bool `json:"llm_record"` // LLM recording switch (default off); takes effect immediately, no agent rebuild needed
	// Web search. WebSearchEnabled/Backend toggle the tool + backend; BraveKey/TavilyKey/KeenableKey
	// are optional — omit (null) to leave a stored key untouched, send "" to clear. The Keenable
	// key is optional even when its backend is selected: empty uses the keyless public endpoint.
	WebSearchEnabled *bool   `json:"web_search_enabled"`
	WebSearchBackend *string `json:"web_search_backend"`
	BraveKey         *string `json:"brave_search_api_key"`
	TavilyKey        *string `json:"tavily_search_api_key"`
	KeenableKey      *string `json:"keenable_search_api_key"`
	WebSearchProxy   *string `json:"web_search_proxy"`   // dedicated egress proxy (http/https/socks5); null = keep, "" = clear
	GlobalProxy      *string `json:"global_proxy"`       // global egress proxy (http/https/socks5); null = keep, "" = clear (direct)
	PythonInterp     *string `json:"python_interpreter"` // python interpreter path for the custom script tool
	Workers          *int    `json:"workers"`            // number of concurrent worker agents (>0); applies to tasks started afterwards
	// task concurrency cap: max simultaneously "running" tasks. Off = unlimited; on, new tasks beyond the cap queue and start automatically as slots free up.
	ConcurrencyEnabled *bool `json:"task_concurrency_enabled"`
	ConcurrencyLimit   *int  `json:"task_concurrency_limit"`
	// LLM failover pool switch + the "fall back to the pool chain even when a bound profile fails" switch. Both need the
	// provider chain rebuilt to take effect.
	LLMPoolEnabled      *bool `json:"llm_pool_enabled"`
	LLMPoolBindFallback *bool `json:"llm_pool_bind_fallback"`
	// operation-constraint injection scope switches (default both on); take effect immediately (planner/worker read them every round), no agent rebuild needed.
	ConstraintsInjectPlanner *bool `json:"constraints_inject_planner"`
	ConstraintsInjectWorker  *bool `json:"constraints_inject_worker"`
	// Experimental: noa context compaction switch (default off); read per run, applies to runs started afterwards, no agent rebuild needed.
	NoaCompaction *bool `json:"noa_compaction"`
	// Vulnerability IM push global settings. The delivery engine re-reads all three every round, so changes
	// take effect immediately with no agent rebuild or restart.
	NotifyEnabled    *bool   `json:"notify_enabled"`
	NotifyBaseURL    *string `json:"notify_public_base_url"`
	NotifyDigestMins *int    `json:"notify_digest_interval_min"`
	// Render limits of IM messages: summary characters (0-4000) and asset names listed (0-50); 0 = no truncation.
	NotifySummaryMaxRunes *int `json:"notify_summary_max_runes"`
	NotifyAssetsMaxShown  *int `json:"notify_assets_max_shown"`
	// Target noise profile: off|quiet|balanced|aggressive; null = unchanged. Applies to the next request, no agent rebuild.
	NoiseProfile *string `json:"noise_profile"`
}

// putSettings validates the whole request, writes every setting, and only then
// switches the live state: noise profile, profile-agent caches, task
// concurrency, and an agent rebuild. A request that fails validation writes
// nothing. Toggling traffic_capture rebuilds the agents (applyLLM) so the new
// proxy/traffic-tools/prompt state takes hold — when off, agents get no proxy
// config, no traffic tools, and no proxy prompt content.
func (s *Server) putSettings(w http.ResponseWriter, r *http.Request) {
	var req putSettingsRequest
	if err := decode(w, r, &req); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	if err := validatePutSettings(&req); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	rebuild, err := s.applyPutSettings(&req)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	if req.NoiseProfile != nil {
		noise, _ := egress.ProfileByName(*req.NoiseProfile)
		egress.SetProfile(noise)
	}
	if req.LLMPoolEnabled != nil || req.LLMPoolBindFallback != nil {
		// Pinned tasks' planner/worker and per-profile chat agents hold providers
		// built under the OLD switch state — drop them so they pick up the new one.
		s.invalidateProfileAgents()
	}
	if req.ConcurrencyEnabled != nil || req.ConcurrencyLimit != nil {
		// Reconcile immediately: turning off releases all queued tasks, raising the cap backfills starts — no need to wait for the next tick.
		go s.reconcileConcurrency()
	}
	if rebuild {
		// rebuild agents so the new proxy/tools/prompt/web-search take hold (only if LLM configured).
		s.cfgMu.Lock()
		cfg, on := s.llmCfg, s.llmOn
		s.cfgMu.Unlock()
		if on {
			if err := s.applyLLM(cfg); err != nil {
				writeErr(w, 500, err.Error())
				return
			}
		}
	}
	writeJSON(w, 200, s.settingsPayload())
}

// validatePutSettings rejects a request before anything is written, and
// normalizes it in place: a masked secret echoed back means "unchanged", the
// noise profile takes its canonical name, and the notify base URL loses
// surrounding space and trailing slashes.
func validatePutSettings(req *putSettingsRequest) error {
	req.BraveKey, req.TavilyKey, req.KeenableKey = keepIfMasked(req.BraveKey), keepIfMasked(req.TavilyKey), keepIfMasked(req.KeenableKey)
	req.WebSearchProxy, req.GlobalProxy = keepIfMasked(req.WebSearchProxy), keepIfMasked(req.GlobalProxy)
	if req.NoiseProfile != nil {
		noise, ok := egress.ProfileByName(*req.NoiseProfile)
		if !ok {
			return errors.New("noise_profile must be off, quiet, balanced or aggressive")
		}
		req.NoiseProfile = &noise.Name
	}
	if req.NotifyBaseURL != nil {
		// Backlinks are joined with fmt.Sprintf("%s/function/..."), and a
		// trailing slash would produce double-slash paths like "//function/...".
		base := trimTrailingSlash(strings.TrimSpace(*req.NotifyBaseURL))
		if base != "" && !strings.HasPrefix(base, "http://") && !strings.HasPrefix(base, "https://") {
			return errors.New("backlink base URL must start with http:// or https://")
		}
		req.NotifyBaseURL = &base
	}
	// 1-minute floor: any shorter period equals realtime push, in which case the channel should just be set to realtime mode.
	if v := req.NotifyDigestMins; v != nil && (*v < 1 || *v > 24*60) {
		return errors.New("digest interval must be between 1 and 1440 minutes")
	}
	if v := req.NotifySummaryMaxRunes; v != nil && (*v < 0 || *v > notifySummaryMaxRunesCap) {
		return fmt.Errorf("summary limit must be between 0 and %d characters (0 = no truncation)", notifySummaryMaxRunesCap)
	}
	if v := req.NotifyAssetsMaxShown; v != nil && (*v < 0 || *v > notifyAssetsMaxShownCap) {
		return fmt.Errorf("asset limit must be between 0 and %d (0 = no truncation)", notifyAssetsMaxShownCap)
	}
	if req.Workers != nil && *req.Workers <= 0 {
		return errors.New("workers must be >0")
	}
	for _, proxy := range []*string{req.GlobalProxy, req.WebSearchProxy} {
		if proxy == nil {
			continue
		}
		if raw := strings.TrimSpace(*proxy); raw != "" {
			if _, err := traffic.ValidateProxyURL(raw); err != nil {
				return err
			}
		}
	}
	return nil
}

// applyPutSettings writes a validated request and reports whether the agents
// must be rebuilt. Settings read straight from the database go first, then the
// ones the Manager also holds in memory, and the noise profile last: putSettings
// switches the live profile only after every write succeeded, so a failed write
// never leaves a stored profile that differs from the one in effect.
func (s *Server) applyPutSettings(req *putSettingsRequest) (rebuild bool, err error) {
	pg := s.m.pg
	if req.ConstraintsInjectPlanner != nil {
		if err := pg.SetBool(settingConstraintsInjectPlanner, *req.ConstraintsInjectPlanner); err != nil {
			return false, err
		}
	}
	if req.ConstraintsInjectWorker != nil {
		if err := pg.SetBool(settingConstraintsInjectWorker, *req.ConstraintsInjectWorker); err != nil {
			return false, err
		}
	}
	if req.NoaCompaction != nil {
		if err := s.m.SetNoaCompaction(*req.NoaCompaction); err != nil {
			return false, err
		}
	}
	if req.NotifyEnabled != nil {
		if err := pg.SetBool(settingNotifyEnabled, *req.NotifyEnabled); err != nil {
			return false, err
		}
	}
	if req.NotifyBaseURL != nil {
		if err := pg.SetSetting(settingNotifyPublicBaseURL, *req.NotifyBaseURL); err != nil {
			return false, err
		}
	}
	if req.NotifyDigestMins != nil {
		if err := pg.SetSetting(settingNotifyDigestMinutes, strconv.Itoa(*req.NotifyDigestMins)); err != nil {
			return false, err
		}
	}
	if req.NotifySummaryMaxRunes != nil {
		if err := pg.SetSetting(settingNotifySummaryMaxRunes, strconv.Itoa(*req.NotifySummaryMaxRunes)); err != nil {
			return false, err
		}
	}
	if req.NotifyAssetsMaxShown != nil {
		if err := pg.SetSetting(settingNotifyAssetsMaxShown, strconv.Itoa(*req.NotifyAssetsMaxShown)); err != nil {
			return false, err
		}
	}
	if req.Workers != nil {
		if err := s.m.SetWorkers(*req.Workers); err != nil {
			return false, err
		}
	}
	if req.ConcurrencyEnabled != nil || req.ConcurrencyLimit != nil {
		// Partial PUT: fields not supplied fall back to current values, so changing one doesn't reset the other.
		on, limit := s.m.ConcurrencyLimit()
		if limit == 0 {
			limit = defaultConcurrencyLimit
		}
		if req.ConcurrencyEnabled != nil {
			on = *req.ConcurrencyEnabled
		}
		if req.ConcurrencyLimit != nil {
			limit = *req.ConcurrencyLimit
		}
		if err := s.m.SetConcurrency(on, limit); err != nil {
			return false, err
		}
	}
	if req.PythonInterp != nil {
		if err := pg.SetSetting(settingPythonInterp, strings.TrimSpace(*req.PythonInterp)); err != nil {
			return false, err
		}
	}
	if req.LLMPoolEnabled != nil {
		if err := s.m.SetLLMPoolEnabled(*req.LLMPoolEnabled); err != nil {
			return false, err
		}
		rebuild = true // the provider chain itself changes shape → rebuild
	}
	if req.LLMPoolBindFallback != nil {
		if err := s.m.SetLLMPoolBindFallback(*req.LLMPoolBindFallback); err != nil {
			return false, err
		}
		rebuild = true
	}
	if req.AgentTrafficBinding != nil {
		if err := pg.SetBool(settingAgentTrafficBinding, *req.AgentTrafficBinding); err != nil {
			return false, err
		}
	}
	if req.LLMRecord != nil {
		if err := s.m.SetLLMRecordEnabled(*req.LLMRecord); err != nil {
			return false, err
		}
	}
	if req.TrafficCapture != nil {
		if err := s.m.SetTrafficEnabled(*req.TrafficCapture); err != nil {
			return false, err
		}
		rebuild = true
	}
	if req.GlobalProxy != nil {
		if err := s.m.SetGlobalProxy(*req.GlobalProxy); err != nil {
			return false, err
		}
		rebuild = true // capture-off egress is baked into agents at build time → rebuild
	}
	if req.WebSearchEnabled != nil || req.WebSearchBackend != nil || req.BraveKey != nil || req.TavilyKey != nil || req.KeenableKey != nil || req.WebSearchProxy != nil {
		// Fill unspecified fields from current state so a partial PUT doesn't reset them.
		on, backend, _, _, _, _ := s.m.WebSearch()
		if req.WebSearchEnabled != nil {
			on = *req.WebSearchEnabled
		}
		if req.WebSearchBackend != nil {
			backend = *req.WebSearchBackend
		}
		if err := s.m.SetWebSearch(on, backend, req.BraveKey, req.TavilyKey, req.KeenableKey, req.WebSearchProxy); err != nil {
			return false, err
		}
		rebuild = true
	}
	if req.NoiseProfile != nil {
		if err := pg.SetSetting(settingNoiseProfile, *req.NoiseProfile); err != nil {
			return false, err
		}
	}
	return rebuild, nil
}
