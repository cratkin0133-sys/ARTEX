package server

import (
	"fmt"
	"strings"

	"github.com/Autumn-27/artex/egress"
	"github.com/Autumn-27/artex/traffic"
)

type putSettingsReq struct {
	TrafficCapture           *bool
	AgentTrafficBinding      *bool
	LLMRecord                *bool
	WebSearchEnabled         *bool
	WebSearchBackend         *string
	BraveKey                 *string
	TavilyKey                *string
	KeenableKey              *string
	WebSearchProxy           *string
	GlobalProxy              *string
	PythonInterp             *string
	Workers                  *int
	ConcurrencyEnabled       *bool
	ConcurrencyLimit         *int
	LLMPoolEnabled           *bool
	LLMPoolBindFallback      *bool
	ConstraintsInjectPlanner *bool
	ConstraintsInjectWorker  *bool
	NoaCompaction            *bool
	NotifyEnabled            *bool
	NotifyBaseURL            *string
	NotifyDigestMins         *int
	NotifySummaryMaxRunes    *int
	NotifyAssetsMaxShown     *int
	NoiseProfile             *string
}

func validatePutSettings(req *putSettingsReq) (egress.Profile, bool, error) {
	var noiseProfile egress.Profile
	if req.NoiseProfile != nil {
		var ok bool
		if noiseProfile, ok = egress.ProfileByName(*req.NoiseProfile); !ok {
			return noiseProfile, false, fmt.Errorf("noise_profile must be off, quiet, balanced or aggressive")
		}
	}
	if req.NotifyBaseURL != nil {
		base := trimTrailingSlash(strings.TrimSpace(*req.NotifyBaseURL))
		if base != "" && !strings.HasPrefix(base, "http://") && !strings.HasPrefix(base, "https://") {
			return noiseProfile, false, fmt.Errorf("backlink base URL must start with http:// or https://")
		}
	}
	if req.NotifyDigestMins != nil {
		if *req.NotifyDigestMins < 1 || *req.NotifyDigestMins > 24*60 {
			return noiseProfile, false, fmt.Errorf("digest interval must be between 1 and 1440 minutes")
		}
	}
	if req.NotifySummaryMaxRunes != nil {
		if *req.NotifySummaryMaxRunes < 0 || *req.NotifySummaryMaxRunes > notifySummaryMaxRunesCap {
			return noiseProfile, false, fmt.Errorf("summary limit must be between 0 and %d characters (0 = no truncation)", notifySummaryMaxRunesCap)
		}
	}
	if req.NotifyAssetsMaxShown != nil {
		if *req.NotifyAssetsMaxShown < 0 || *req.NotifyAssetsMaxShown > notifyAssetsMaxShownCap {
			return noiseProfile, false, fmt.Errorf("asset limit must be between 0 and %d (0 = no truncation)", notifyAssetsMaxShownCap)
		}
	}
	if req.Workers != nil && *req.Workers <= 0 {
		return noiseProfile, false, fmt.Errorf("workers must be >0")
	}
	if req.GlobalProxy != nil {
		raw := strings.TrimSpace(*req.GlobalProxy)
		if raw != "" {
			if _, err := traffic.ValidateProxyURL(raw); err != nil {
				return noiseProfile, false, err
			}
		}
	}
	if req.WebSearchProxy != nil {
		raw := strings.TrimSpace(*req.WebSearchProxy)
		if raw != "" {
			if _, err := traffic.ValidateProxyURL(raw); err != nil {
				return noiseProfile, false, err
			}
		}
	}
	noiseChosen := req.NoiseProfile != nil
	return noiseProfile, noiseChosen, nil
}
