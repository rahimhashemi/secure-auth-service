-- Exact email lookup relies on canonical stored values. Preserve identities: do not rewrite rows.
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM users WHERE email <> lower(btrim(email))) THEN
        RAISE EXCEPTION 'Non-canonical user emails found. Reconcile legacy identities before using exact lookup.';
    END IF;
END;
$$;
