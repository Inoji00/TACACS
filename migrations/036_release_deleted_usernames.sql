BEGIN;
DO $$
DECLARE
    removed_user uuid;
BEGIN
    FOR removed_user IN SELECT id FROM users WHERE deleted LOOP
        BEGIN
            DELETE FROM users WHERE id = removed_user;
        EXCEPTION WHEN foreign_key_violation THEN
            UPDATE users
            SET username = ':deleted:' || id::text, password_hash = '!'
            WHERE id = removed_user;
        END;
    END LOOP;
END;
$$;
COMMIT;
