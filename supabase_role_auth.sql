-- KBuild Network: OTP + role-based single-app architecture
-- Run this once in Supabase SQL Editor after enabling Phone/SMS Auth.

CREATE TABLE IF NOT EXISTS public.kbuild_profiles (
  id uuid PRIMARY KEY REFERENCES auth.users(id) ON DELETE CASCADE,
  phone text UNIQUE NOT NULL,
  email text,
  full_name text NOT NULL,
  role text NOT NULL CHECK (role IN ('customer','partner')),
  approval_status text NOT NULL DEFAULT 'approved' CHECK (approval_status IN ('pending','approved','rejected')),
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);

ALTER TABLE public.kbuild_profiles ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS "kbuild_profiles_select_own" ON public.kbuild_profiles;
CREATE POLICY "kbuild_profiles_select_own" ON public.kbuild_profiles
FOR SELECT TO authenticated USING (id = auth.uid());

DROP POLICY IF EXISTS "kbuild_profiles_update_own" ON public.kbuild_profiles;
CREATE POLICY "kbuild_profiles_update_own" ON public.kbuild_profiles
FOR UPDATE TO authenticated USING (id = auth.uid()) WITH CHECK (id = auth.uid());

CREATE OR REPLACE FUNCTION public.get_my_kbuild_profile()
RETURNS SETOF public.kbuild_profiles
LANGUAGE sql STABLE SECURITY INVOKER SET search_path=public
AS $$ SELECT * FROM public.kbuild_profiles WHERE id = auth.uid() LIMIT 1 $$;

CREATE OR REPLACE FUNCTION public.create_my_kbuild_profile(
  p_role text,
  p_full_name text,
  p_email text DEFAULT NULL
)
RETURNS public.kbuild_profiles
LANGUAGE plpgsql SECURITY DEFINER SET search_path=public
AS $$
DECLARE
  u auth.users;
  result public.kbuild_profiles;
  phone_value text;
BEGIN
  SELECT * INTO u FROM auth.users WHERE id = auth.uid();
  IF u.id IS NULL THEN RAISE EXCEPTION 'Authentication session not found'; END IF;
  phone_value := regexp_replace(coalesce(u.phone,''),'[^0-9]','','g');
  IF length(phone_value) >= 10 THEN phone_value := right(phone_value,10); END IF;
  IF p_role NOT IN ('customer','partner') THEN RAISE EXCEPTION 'Invalid role'; END IF;
  IF trim(coalesce(p_full_name,'')) = '' THEN RAISE EXCEPTION 'Name is required'; END IF;
  INSERT INTO public.kbuild_profiles(id,phone,email,full_name,role,approval_status,updated_at)
  VALUES (u.id,phone_value,NULLIF(trim(p_email),''),trim(p_full_name),p_role,CASE WHEN p_role='partner' THEN 'pending' ELSE 'approved' END,now())
  ON CONFLICT (id) DO UPDATE SET phone=excluded.phone,email=excluded.email,full_name=excluded.full_name,role=excluded.role,updated_at=now()
  RETURNING * INTO result;
  RETURN result;
END $$;

GRANT EXECUTE ON FUNCTION public.get_my_kbuild_profile() TO authenticated;
GRANT EXECUTE ON FUNCTION public.create_my_kbuild_profile(text,text,text) TO authenticated;

-- Link vendor records to the authenticated owner where possible.
ALTER TABLE public.vendors ADD COLUMN IF NOT EXISTS auth_user_id uuid REFERENCES auth.users(id) ON DELETE SET NULL;
CREATE INDEX IF NOT EXISTS vendors_auth_user_id_idx ON public.vendors(auth_user_id);

-- Existing partner rows can be linked later by phone after their first OTP login.
-- Do not make public partner discovery dependent on this column; approved profiles remain discoverable.

-- Phone OTP must be enabled in Supabase Dashboard -> Authentication -> Providers -> Phone.

CREATE OR REPLACE FUNCTION public.kbuild_sync_partner_approval()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path=public
AS $$
BEGIN
  IF NEW.auth_user_id IS NOT NULL THEN
    UPDATE public.kbuild_profiles
    SET approval_status = CASE
      WHEN lower(trim(coalesce(NEW.status,''))) = 'approved' THEN 'approved'
      WHEN lower(trim(coalesce(NEW.status,''))) = 'rejected' THEN 'rejected'
      ELSE 'pending'
    END,
    updated_at = now()
    WHERE id = NEW.auth_user_id AND role = 'partner';
  END IF;
  RETURN NEW;
END $$;

DROP TRIGGER IF EXISTS kbuild_sync_partner_approval_trigger ON public.vendors;
CREATE TRIGGER kbuild_sync_partner_approval_trigger
AFTER INSERT OR UPDATE OF status, auth_user_id ON public.vendors
FOR EACH ROW EXECUTE FUNCTION public.kbuild_sync_partner_approval();

-- Admin approval controls for partner onboarding.
CREATE OR REPLACE FUNCTION public.admin_set_partner_status(
  p_admin_phone text,
  p_partner_id bigint,
  p_status text
)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
  v_phone text := right(regexp_replace(coalesce(p_admin_phone,''),'[^0-9]','','g'),10);
  v_status text := lower(trim(coalesce(p_status,'')));
  v_vendor public.vendors;
  v_profile public.kbuild_profiles;
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM public.kbuild_admins
    WHERE right(regexp_replace(coalesce(phone,''),'[^0-9]','','g'),10)=v_phone
      AND coalesce(active,true)=true
  ) THEN
    RAISE EXCEPTION 'Admin access denied';
  END IF;

  IF v_status NOT IN ('approved','rejected','pending') THEN
    RAISE EXCEPTION 'Invalid partner status';
  END IF;

  UPDATE public.vendors
  SET status=v_status
  WHERE id=p_partner_id
  RETURNING * INTO v_vendor;

  IF v_vendor.id IS NULL THEN
    RAISE EXCEPTION 'Partner not found';
  END IF;

  IF v_vendor.auth_user_id IS NOT NULL THEN
    UPDATE public.kbuild_profiles
    SET approval_status=v_status, updated_at=now()
    WHERE id=v_vendor.auth_user_id AND role='partner'
    RETURNING * INTO v_profile;
  END IF;

  RETURN jsonb_build_object(
    'success',true,
    'partner_id',v_vendor.id,
    'status',v_status,
    'business_name',v_vendor.business_name,
    'phone',v_vendor.phone
  );
END $$;

GRANT EXECUTE ON FUNCTION public.admin_set_partner_status(text,bigint,text) TO anon, authenticated;
