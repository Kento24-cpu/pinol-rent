-- Best-practices hardening (P1): add indexes on RLS-filtered / app-queried columns.
-- Postgres does NOT auto-index foreign keys, so these were missing and caused
-- sequential scans on every RLS evaluation and on the most common app queries.

create index if not exists idx_notification_prefs_user_id on notification_prefs(user_id);

create index if not exists idx_reviews_renter_id on reviews(renter_id);
