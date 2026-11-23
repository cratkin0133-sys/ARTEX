package db

import (
	"context"
	"database/sql"
)

// AgentConfigPatch groups optional agent runtime config updates for one transaction.
type AgentConfigPatch struct {
	MaxTurns         *int
	RunSeconds       *int
	WebSearch        *bool
	InteractiveShell *bool
	LLMProfileID     *int64 // nil pointer in patch means clear binding; absent field handled by caller
	ClearLLMProfile  bool
	TriggerRunMode   *string
	TriggerMergeMode *string
	TriggerMaxPar    *int
}

// PatchAgentConfig applies all provided fields in one transaction.
func (d *DB) PatchAgentConfig(ctx context.Context, key string, patch AgentConfigPatch) (bool, error) {
	tx, err := d.BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	defer tx.Rollback()

	var agentID int64
	if err := tx.QueryRowContext(ctx, `SELECT id FROM agents WHERE key=$1 FOR UPDATE`, key).Scan(&agentID); err != nil {
		if err == sql.ErrNoRows {
			return false, nil
		}
		return false, err
	}

	if patch.ClearLLMProfile || patch.LLMProfileID != nil {
		var profileID *int64
		if !patch.ClearLLMProfile {
			profileID = patch.LLMProfileID
		}
		if err := lockLLMProfileForReference(tx, profileID); err != nil {
			return false, err
		}
		if _, err := tx.ExecContext(ctx, `UPDATE agents SET llm_profile_id=$1 WHERE id=$2`, profileID, agentID); err != nil {
			return false, err
		}
	}
	if patch.MaxTurns != nil {
		mt := *patch.MaxTurns
		if mt < 0 {
			mt = 0
		}
		if _, err := tx.ExecContext(ctx, `UPDATE agents SET max_turns=$1 WHERE id=$2`, mt, agentID); err != nil {
			return false, err
		}
	}
	if patch.RunSeconds != nil {
		rs := *patch.RunSeconds
		if rs < 0 {
			rs = 0
		}
		if _, err := tx.ExecContext(ctx, `UPDATE agents SET run_seconds=$1 WHERE id=$2`, rs, agentID); err != nil {
			return false, err
		}
	}
	if patch.WebSearch != nil {
		if _, err := tx.ExecContext(ctx, `UPDATE agents SET web_search=$1 WHERE id=$2`, *patch.WebSearch, agentID); err != nil {
			return false, err
		}
	}
	if patch.InteractiveShell != nil {
		if _, err := tx.ExecContext(ctx, `UPDATE agents SET interactive_shell=$1 WHERE id=$2`, *patch.InteractiveShell, agentID); err != nil {
			return false, err
		}
	}
	if patch.TriggerRunMode != nil || patch.TriggerMergeMode != nil || patch.TriggerMaxPar != nil {
		var runMode, mergeMode string
		var maxPar int
		if err := tx.QueryRowContext(ctx, `SELECT trigger_run_mode, trigger_merge_mode, trigger_max_parallel FROM agents WHERE id=$1`, agentID).
			Scan(&runMode, &mergeMode, &maxPar); err != nil {
			return false, err
		}
		if patch.TriggerRunMode != nil {
			runMode = *patch.TriggerRunMode
		}
		if patch.TriggerMergeMode != nil {
			mergeMode = *patch.TriggerMergeMode
		}
		if patch.TriggerMaxPar != nil {
			maxPar = *patch.TriggerMaxPar
		}
		switch runMode {
		case "serial", "parallel":
		default:
			runMode = "serial"
		}
		switch mergeMode {
		case "by_task", "all", "none":
		default:
			mergeMode = "by_task"
		}
		if maxPar < 0 {
			maxPar = 0
		}
		if _, err := tx.ExecContext(ctx, `UPDATE agents SET trigger_run_mode=$1, trigger_merge_mode=$2, trigger_max_parallel=$3 WHERE id=$4`,
			runMode, mergeMode, maxPar, agentID); err != nil {
			return false, err
		}
	}

	if err := tx.Commit(); err != nil {
		return false, err
	}
	return true, nil
}
