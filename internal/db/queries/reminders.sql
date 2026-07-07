-- name: GetDueReminders :many
SELECT * FROM reminders
WHERE next_fire_at <= now() AND fires_remaining > 0
LIMIT $1;

-- name: AdvanceReminder :exec
UPDATE reminders
SET last_fired_at = now(),
    next_fire_at = $2,
    fires_remaining = fires_remaining - 1
WHERE document_id = $1;

-- name: CancelReminder :exec
DELETE FROM reminders WHERE document_id = $1;

-- name: UpsertReminderSchedule :exec
-- Replaces the inline reminder-upsert SQL the REST + MCP send paths used.
INSERT INTO reminders (document_id, schedule_json, next_fire_at, fires_remaining)
VALUES ($1, $2::jsonb, now() + interval '3 days', $3)
ON CONFLICT (document_id) DO UPDATE
  SET schedule_json   = EXCLUDED.schedule_json,
      next_fire_at    = EXCLUDED.next_fire_at,
      fires_remaining = EXCLUDED.fires_remaining;

-- name: ResetReminderAfterManualRemind :exec
-- A manual remind pushes the next scheduled auto-fire out so the worker
-- doesn't double-send right after.
UPDATE reminders
SET next_fire_at = now() + interval '3 days', last_fired_at = now()
WHERE document_id = $1;
