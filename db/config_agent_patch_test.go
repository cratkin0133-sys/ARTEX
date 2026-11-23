package db

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"
)

func TestPatchAgentConfig(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		SkipPGUnavailable(t, err)
	}
	t.Cleanup(func() { d.Close() })
	ctx := context.Background()
	suffix := time.Now().UnixNano()
	profileID, err := d.SaveProfile(&LLMProfile{
		Name: fmt.Sprintf("patch-agent-profile-%d", suffix), Format: "openai", Model: "patch-agent", APIKey: "test-key",
	})
	if err != nil {
		t.Fatal(err)
	}
	created, err := d.CreateAgent(fmt.Sprintf("patch_agent_%d", suffix), "patch agent", "")
	if err != nil {
		_ = d.DeleteProfile(profileID)
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = d.DeleteAgent(created.Key)
		_ = d.DeleteProfile(profileID)
	})
	get := func() *Agent {
		t.Helper()
		a, err := d.GetAgentByKey(created.Key)
		if err != nil || a == nil {
			t.Fatalf("GetAgentByKey: %+v err=%v", a, err)
		}
		return a
	}
	patch := func(p AgentConfigPatch) error {
		t.Helper()
		found, err := d.PatchAgentConfig(ctx, created.Key, p)
		if err == nil && !found {
			t.Fatal("PatchAgentConfig: agent not found")
		}
		return err
	}

	maxTurns, runSecs, on, parallel, maxPar := 12, -5, true, "parallel", 3
	bound := &profileID
	if err := patch(AgentConfigPatch{
		MaxTurns: &maxTurns, RunSeconds: &runSecs, WebSearch: &on, InteractiveShell: &on,
		LLMProfileID: &bound, TriggerRunMode: &parallel, TriggerMaxParallel: &maxPar,
	}); err != nil {
		t.Fatal(err)
	}
	a := get()
	if a.MaxTurns != 12 || a.RunSecs != 0 || !a.WebSearch || !a.InteractiveShell ||
		a.LLMProfileID == nil || *a.LLMProfileID != profileID ||
		a.TriggerRunMode != "parallel" || a.TriggerMaxParallel != 3 || a.TriggerMergeMode != created.TriggerMergeMode {
		t.Fatalf("after full patch: %+v", a)
	}

	bogus := "bogus"
	if err := patch(AgentConfigPatch{TriggerMergeMode: &bogus}); err != nil {
		t.Fatal(err)
	}
	if a := get(); a.TriggerMergeMode != "by_task" || a.TriggerRunMode != "parallel" || a.TriggerMaxParallel != 3 ||
		a.MaxTurns != 12 || a.LLMProfileID == nil {
		t.Fatalf("a partial patch must change only its own field (unknown merge mode -> by_task): %+v", a)
	}

	missing := int64(-1)
	missingRef, otherTurns := &missing, 99
	if err := patch(AgentConfigPatch{MaxTurns: &otherTurns, LLMProfileID: &missingRef}); !errors.Is(err, ErrLLMProfileNotFound) {
		t.Fatalf("binding a missing profile: want ErrLLMProfileNotFound, got %v", err)
	}
	if a := get(); a.MaxTurns != 12 || a.LLMProfileID == nil || *a.LLMProfileID != profileID {
		t.Fatalf("a failed patch must write nothing: %+v", a)
	}

	var unbound *int64
	if err := patch(AgentConfigPatch{LLMProfileID: &unbound}); err != nil {
		t.Fatal(err)
	}
	if a := get(); a.LLMProfileID != nil {
		t.Fatalf("a pointer to nil must unbind: %+v", a)
	}

	if found, err := d.PatchAgentConfig(ctx, fmt.Sprintf("missing_agent_%d", suffix), AgentConfigPatch{MaxTurns: &maxTurns}); err != nil || found {
		t.Fatalf("unknown key: found=%v err=%v", found, err)
	}
}
