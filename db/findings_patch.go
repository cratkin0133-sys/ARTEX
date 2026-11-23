package db

import (
	"context"
	"database/sql"
)

// FindingPatch holds the finding fields one PATCH changes; nil leaves a field
// as it is. Callers validate the values: PatchFinding writes them as given.
type FindingPatch struct {
	Status      *string
	ReportState *string
	Severity    *string
	Name        *string
	VulnClass   *string
}

// PatchFinding applies every set field of patch in one transaction and returns
// the updated finding. found is false, with nothing written, when no finding has
// that id; an error rolls the whole patch back. The text fields are written
// before the status, so a status-change notification describes the finding as
// the patch leaves it. Notification and lesson semantics match
// SetFindingStatusWithNotify.
func (d *DB) PatchFinding(ctx context.Context, id int64, patch FindingPatch) (f *DBFinding, found bool, err error) {
	err = d.WithEvidenceTx(ctx, func(tx *sql.Tx) error {
		var nodeID sql.NullInt64
		switch err := tx.QueryRowContext(ctx, `SELECT node_id FROM findings WHERE id=$1 FOR UPDATE`, id).Scan(&nodeID); {
		case err == sql.ErrNoRows:
			return nil
		case err != nil:
			return err
		}
		found = true
		for _, field := range []struct {
			col string
			val *string
		}{{"severity", patch.Severity}, {"name", patch.Name}, {"vulnclass", patch.VulnClass}} {
			if field.val == nil {
				continue
			}
			if err := setFindingTextTx(ctx, tx, id, nodeID, field.col, *field.val); err != nil {
				return err
			}
		}
		if patch.ReportState != nil {
			if _, _, _, err := setFindingReportStateTx(ctx, tx, id, *patch.ReportState); err != nil {
				return err
			}
		}
		if patch.Status != nil {
			_, _, changed, _, err := SetFindingStatusTx(ctx, tx, id, *patch.Status)
			if err != nil {
				return err
			}
			if changed {
				return syncLessonsForFindingTx(ctx, tx, id)
			}
		}
		return nil
	})
	if err != nil || !found {
		return nil, false, err
	}
	f, err = d.GetFinding(id)
	return f, f != nil, err
}

// setFindingTextTx writes one text column of a finding and mirrors it onto the
// originating node's payload under the same key, which the per-task view reads.
// col is interpolated into the SQL, so it must be a trusted constant.
func setFindingTextTx(ctx context.Context, tx *sql.Tx, id int64, nodeID sql.NullInt64, col, val string) error {
	if _, err := tx.ExecContext(ctx, `UPDATE findings SET `+col+`=$2 WHERE id=$1`, id, val); err != nil {
		return err
	}
	if !nodeID.Valid {
		return nil
	}
	_, err := tx.ExecContext(ctx, `UPDATE exploration_nodes
		SET payload = jsonb_set(payload, '{`+col+`}', to_jsonb($1::text))
		WHERE id = $2`, val, nodeID.Int64)
	return err
}
