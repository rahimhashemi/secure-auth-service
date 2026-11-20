-- Legacy sessions are not automatically elevated; new login sessions receive a fresh timestamp.
-- The backend checks this column in PostgreSQL on each sensitive session mutation.
ALTER TABLE auth_sessions ADD COLUMN last_step_up_at TIMESTAMP(6) WITH TIME ZONE;
