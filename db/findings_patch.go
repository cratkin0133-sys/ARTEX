package db

import (
	"context"
	"database/sql"
)

// FindingPatch carries optional finding field updates for one atomic patch.
type FindingPatch struct {
	Status      *string
	ReportState *string
	Severity    *string
	Name        *string
	VulnClass   *string
}

func setFindingTextColTx(ctx context.Context, tx *sql.Tx, id int64, col, jsonKey, val string) (found bool, changed bool, err error) {
	var nodeID sql.NullInt64
	var cur string
	scanErr := tx.QueryRowContext(ctx, `SELECT `+col+`, node_id FROM findings WHERE id=$1 FOR UPDATE`, id).Scan(&cur, &nodeID)
	if scanErr == sql.ErrNoRows {
		return false, false, nil
	}
	if scanErr != nil {
		return false, false, scanErr
	}
	if cur == val {
		return true, false, nil
	}
	if _, err := tx.ExecContext(ctx, `UPDATE findings SET `+col+`=$2 WHERE id=$1`, id, val); err != nil {
		return true, false, err
	}
	if nodeID.Valid {
		if _, err := tx.ExecContext(ctx, `UPDATE exploration_nodes
			SET payload = jsonb_set(payload, '{`+jsonKey+`}', to_jsonb($1::text))
			WHERE id = $2`, val, nodeID.Int64); err != nil {
			return true, false, err
		}
	}
	return true, true, nil
}

// PatchFinding applies every set field in patch in one transaction. When status
// changes, notification semantics match SetFindingStatusWithNotify. Returns the
// updated row, whether the finding existed, and any database error (full rollback).
func (d *DB) PatchFinding(ctx context.Context, id int64, patch FindingPatch) (*DBFinding, bool, error) {
	if patch.Status == nil && patch.ReportState == nil && patch.Severity == nil &&
		patch.Name == nil && patch.VulnClass == nil {
		return nil, false, nil
	}
	var found bool
	err := d.WithEvidenceTx(ctx, func(tx *sql.Tx) error {
		if patch.Status != nil {
			_, f, changed, _, txErr := SetFindingStatusTx(ctx, tx, id, *patch.Status)
			if txErr != nil {
				return txErr
			}
			if !f {
				found = false
				return nil
			}
			found = true
			if changed {
				if err := syncLessonsForFindingTx(ctx, tx, id); err != nil {
					return err
				}
			}
		}
		if patch.ReportState != nil {
			_, f, _, txErr := setFindingReportStateTx(ctx, tx, id, *patch.ReportState)
			if txErr != nil {
				return txErr
			}
			if !f {
				found = false
				return nil
			}
			found = true
		}
		if patch.Severity != nil {
			f, _, txErr := setFindingTextColTx(ctx, tx, id, "severity", "severity", *patch.Severity)
			if txErr != nil {
				return txErr
			}
			if !f {
				found = false
				return nil
			}
			found = true
		}
		if patch.Name != nil {
			f, _, txErr := setFindingTextColTx(ctx, tx, id, "name", "name", *patch.Name)
			if txErr != nil {
				return txErr
			}
			if !f {
				found = false
				return nil
			}
			found = true
		}
		if patch.VulnClass != nil {
			f, _, txErr := setFindingTextColTx(ctx, tx, id, "vulnclass", "vulnclass", *patch.VulnClass)
			if txErr != nil {
				return txErr
			}
			if !f {
				found = false
				return nil
			}
			found = true
		}
		return nil
	})
	if err != nil {
		return nil, false, err
	}
	if !found {
		return nil, false, nil
	}
	out, err := d.GetFinding(id)
	if err != nil {
		return nil, true, err
	}
	if out == nil {
		return nil, false, nil
	}
	return out, true, nil
}
