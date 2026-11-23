package db

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
)

// AgentConfigPatch holds the agent runtime settings one config save changes;
// nil leaves a setting as it is. LLMProfileID is tri-state: nil leaves the
// binding, a pointer to nil unbinds, a pointer to an id binds that profile.
type AgentConfigPatch struct {
	MaxTurns           *int
	RunSeconds         *int
	WebSearch          *bool
	InteractiveShell   *bool
	LLMProfileID       **int64
	TriggerRunMode     *string
	TriggerMergeMode   *string
	TriggerMaxParallel *int
}

// PatchAgentConfig writes every set field of patch with one UPDATE in one
// transaction, so a failure leaves the agent unchanged. found is false, with
// nothing written, when no agent has that key. Negative budgets clamp to 0 and
// unknown trigger modes fall back to their defaults. Binding a profile that
// does not exist returns ErrLLMProfileNotFound.
func (d *DB) PatchAgentConfig(ctx context.Context, key string, patch AgentConfigPatch) (found bool, err error) {
	tx, err := d.BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	defer tx.Rollback()

	// DeleteProfile locks reference rows before the profile row. Keep the same
	// order here so a concurrent rebind cannot form a child/profile deadlock.
	var agentID int64
	switch err := tx.QueryRowContext(ctx, `SELECT id FROM agents WHERE key=$1 FOR UPDATE`, key).Scan(&agentID); {
	case err == sql.ErrNoRows:
		return false, nil
	case err != nil:
		return false, err
	}
	args := []any{agentID}
	var sets []string
	set := func(col string, v any) {
		args = append(args, v)
		sets = append(sets, fmt.Sprintf("%s=$%d", col, len(args)))
	}
	if patch.LLMProfileID != nil {
		if err := lockLLMProfileForReference(tx, *patch.LLMProfileID); err != nil {
			return true, err
		}
		set("llm_profile_id", *patch.LLMProfileID)
	}
	if patch.MaxTurns != nil {
		set("max_turns", max(*patch.MaxTurns, 0))
	}
	if patch.RunSeconds != nil {
		set("run_seconds", max(*patch.RunSeconds, 0))
	}
	if patch.WebSearch != nil {
		set("web_search", *patch.WebSearch)
	}
	if patch.InteractiveShell != nil {
		set("interactive_shell", *patch.InteractiveShell)
	}
	if patch.TriggerRunMode != nil {
		set("trigger_run_mode", triggerRunMode(*patch.TriggerRunMode))
	}
	if patch.TriggerMergeMode != nil {
		set("trigger_merge_mode", triggerMergeMode(*patch.TriggerMergeMode))
	}
	if patch.TriggerMaxParallel != nil {
		set("trigger_max_parallel", max(*patch.TriggerMaxParallel, 0))
	}
	if len(sets) > 0 {
		if _, err := tx.ExecContext(ctx, `UPDATE agents SET `+strings.Join(sets, ", ")+` WHERE id=$1`, args...); err != nil {
			return true, err
		}
	}
	return true, tx.Commit()
}

// triggerRunMode whitelists a trigger run mode so dirty input cannot throw off
// the scheduling pump; anything unknown runs serially.
func triggerRunMode(mode string) string {
	if mode == "parallel" {
		return mode
	}
	return "serial"
}

// triggerMergeMode whitelists a serial-queue merge mode; anything unknown
// merges by task.
func triggerMergeMode(mode string) string {
	switch mode {
	case "all", "none":
		return mode
	}
	return "by_task"
}
