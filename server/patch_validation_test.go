package server

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/egress"
)

// A settings PUT with one invalid field is rejected whole: the valid fields
// sent with it are not written either.
func TestPutSettingsValidatesBeforeWriting(t *testing.T) {
	s, _, request := trafficEvidenceServer(t)
	pg := s.m.pg
	keys := []string{settingWorkers, settingNotifyEnabled, settingNoiseProfile}
	clear := func() {
		for _, k := range keys {
			if _, err := pg.Exec(`DELETE FROM settings WHERE key=$1`, k); err != nil {
				t.Error(err)
			}
		}
	}
	clear()
	t.Cleanup(clear)
	prev := egress.CurrentProfile()
	t.Cleanup(func() { egress.SetProfile(prev) })

	for _, body := range []string{
		`{"notify_enabled":true,"workers":0}`,
		`{"workers":7,"global_proxy":"ftp://proxy.example:21"}`,
		`{"workers":7,"web_search_proxy":"ftp://proxy.example:21"}`,
		`{"workers":7,"notify_digest_interval_min":0}`,
		`{"workers":7,"notify_public_base_url":"ftp://x"}`,
		`{"workers":7,"noise_profile":"loud"}`,
	} {
		if r := request("PUT", "/api/settings", body); r.Code != 400 {
			t.Errorf("%s: HTTP %d, want 400", body, r.Code)
		}
		for _, k := range keys {
			if v, ok, _ := pg.GetSetting(k); ok {
				t.Fatalf("%s was rejected but wrote %s=%q", body, k, v)
			}
		}
	}

	if r := request("PUT", "/api/settings", `{"workers":7,"notify_enabled":true,"noise_profile":"Quiet"}`); r.Code != 200 {
		t.Fatalf("valid PUT: HTTP %d %s", r.Code, r.Body)
	}
	for k, want := range map[string]string{settingWorkers: "7", settingNotifyEnabled: "true", settingNoiseProfile: "quiet"} {
		if v, _, _ := pg.GetSetting(k); v != want {
			t.Errorf("after a valid PUT %s=%q, want %q", k, v, want)
		}
	}
	if p := egress.CurrentProfile(); p.Name != "quiet" {
		t.Errorf("live noise profile %q, want quiet", p.Name)
	}
}

// A finding PATCH with one invalid field is rejected whole, and a valid one
// lands every field it carries.
func TestPatchFindingValidatesBeforeWriting(t *testing.T) {
	s, f, request := trafficEvidenceServer(t)
	path := fmt.Sprintf("/api/exploration/findings/%d", f.FindingID)
	before, err := s.m.pg.GetFinding(f.FindingID)
	if err != nil || before == nil {
		t.Fatalf("GetFinding: %+v err=%v", before, err)
	}
	for _, body := range []string{
		`{"status":"confirmed","severity":"bogus"}`,
		`{"severity":"critical","report_state":"bogus"}`,
		`{"name":"renamed","status":"bogus"}`,
	} {
		if r := request("PATCH", path, body); r.Code != 400 {
			t.Errorf("%s: HTTP %d, want 400", body, r.Code)
		}
	}
	after, err := s.m.pg.GetFinding(f.FindingID)
	if err != nil || after == nil {
		t.Fatalf("GetFinding: %+v err=%v", after, err)
	}
	if after.Status != before.Status || after.Severity != before.Severity || after.Name != before.Name || after.ReportState != before.ReportState {
		t.Fatalf("rejected patches wrote fields:\nbefore %+v\nafter  %+v", before, after)
	}

	r := request("PATCH", path, `{"status":"confirmed","severity":"critical","name":" renamed ","report_state":"submitted"}`)
	if r.Code != 200 {
		t.Fatalf("valid PATCH: HTTP %d %s", r.Code, r.Body)
	}
	var got FindingDTO
	if err := json.Unmarshal(r.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.Status != db.FindingConfirmed || got.Severity != "critical" || got.Name != "renamed" || got.ReportState != db.FindingReportSubmitted {
		t.Fatalf("valid PATCH returned %+v", got)
	}
	if r := request("PATCH", "/api/exploration/findings/999999999", `{"severity":"low"}`); r.Code != 404 {
		t.Fatalf("unknown finding: HTTP %d, want 404", r.Code)
	}
}
