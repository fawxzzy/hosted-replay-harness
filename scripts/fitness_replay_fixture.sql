\set ON_ERROR_STOP on
BEGIN;

-- Synthetic-only identities. Labels are comments and receipt vocabulary, never user data.
INSERT INTO auth.users (
  id, instance_id, aud, role, raw_app_meta_data, raw_user_meta_data, created_at, updated_at
) VALUES
  ('f1000000-0000-4000-8000-000000000000', '00000000-0000-0000-0000-000000000000', 'authenticated', 'authenticated', '{"provider":"synthetic"}', '{}', clock_timestamp(), clock_timestamp()),
  ('f1000000-0000-4000-8000-000000000001', '00000000-0000-0000-0000-000000000000', 'authenticated', 'authenticated', '{"provider":"synthetic"}', '{}', clock_timestamp(), clock_timestamp()),
  ('f1000000-0000-4000-8000-000000000002', '00000000-0000-0000-0000-000000000000', 'authenticated', 'authenticated', '{"provider":"synthetic"}', '{}', clock_timestamp(), clock_timestamp()),
  ('f1000000-0000-4000-8000-000000000003', '00000000-0000-0000-0000-000000000000', 'authenticated', 'authenticated', '{"provider":"synthetic"}', '{}', clock_timestamp(), clock_timestamp()),
  ('f1000000-0000-4000-8000-000000000004', '00000000-0000-0000-0000-000000000000', 'authenticated', 'authenticated', '{"provider":"synthetic"}', '{}', clock_timestamp(), clock_timestamp()),
  ('f1000000-0000-4000-8000-000000000005', '00000000-0000-0000-0000-000000000000', 'authenticated', 'authenticated', '{"provider":"synthetic"}', '{}', clock_timestamp(), clock_timestamp()),
  ('fa000000-0000-4000-8000-000000000000', '00000000-0000-0000-0000-000000000000', 'authenticated', 'authenticated', '{"provider":"synthetic","account_kind":"automation"}', '{}', clock_timestamp(), clock_timestamp());

-- #0 is the controlled legacy reservation that must exist before candidate migration 102.
INSERT INTO public.profiles (id, user_number, user_kind, user_number_assigned_at)
VALUES ('f1000000-0000-4000-8000-000000000000', 0, 'human', clock_timestamp());

INSERT INTO public.profiles (id) VALUES
  ('f1000000-0000-4000-8000-000000000001'),
  ('f1000000-0000-4000-8000-000000000002'),
  ('f1000000-0000-4000-8000-000000000003'),
  ('f1000000-0000-4000-8000-000000000004'),
  ('f1000000-0000-4000-8000-000000000005'),
  ('fa000000-0000-4000-8000-000000000000');

COMMIT;
