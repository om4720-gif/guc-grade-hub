CREATE TABLE public.guc_accounts (
  user_id uuid PRIMARY KEY,
  guc_username text NOT NULL,
  password_cipher text NOT NULL,
  last_synced_at timestamptz,
  last_error text,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);
GRANT SELECT, DELETE ON public.guc_accounts TO authenticated;
GRANT ALL ON public.guc_accounts TO service_role;
ALTER TABLE public.guc_accounts ENABLE ROW LEVEL SECURITY;
CREATE POLICY "own account read" ON public.guc_accounts FOR SELECT TO authenticated USING (auth.uid() = user_id);
CREATE POLICY "own account delete" ON public.guc_accounts FOR DELETE TO authenticated USING (auth.uid() = user_id);

CREATE TABLE public.grades (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id uuid NOT NULL,
  course text NOT NULL,
  item text NOT NULL,
  grade text NOT NULL,
  fingerprint text NOT NULL,
  first_seen_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (user_id, course, item)
);
CREATE INDEX grades_user_idx ON public.grades(user_id);
GRANT SELECT ON public.grades TO authenticated;
GRANT ALL ON public.grades TO service_role;
ALTER TABLE public.grades ENABLE ROW LEVEL SECURITY;
CREATE POLICY "own grades read" ON public.grades FOR SELECT TO authenticated USING (auth.uid() = user_id);

CREATE TABLE public.api_keys (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id uuid NOT NULL,
  name text NOT NULL,
  key_prefix text NOT NULL,
  key_hash text NOT NULL UNIQUE,
  last_used_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now()
);
GRANT SELECT, DELETE ON public.api_keys TO authenticated;
GRANT ALL ON public.api_keys TO service_role;
ALTER TABLE public.api_keys ENABLE ROW LEVEL SECURITY;
CREATE POLICY "own keys read" ON public.api_keys FOR SELECT TO authenticated USING (auth.uid() = user_id);
CREATE POLICY "own keys delete" ON public.api_keys FOR DELETE TO authenticated USING (auth.uid() = user_id);

CREATE TABLE public.webhooks (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id uuid NOT NULL,
  url text NOT NULL,
  signing_secret text NOT NULL,
  last_status text,
  last_called_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now()
);
GRANT SELECT, DELETE ON public.webhooks TO authenticated;
GRANT ALL ON public.webhooks TO service_role;
ALTER TABLE public.webhooks ENABLE ROW LEVEL SECURITY;
CREATE POLICY "own hooks read" ON public.webhooks FOR SELECT TO authenticated USING (auth.uid() = user_id);
CREATE POLICY "own hooks delete" ON public.webhooks FOR DELETE TO authenticated USING (auth.uid() = user_id);