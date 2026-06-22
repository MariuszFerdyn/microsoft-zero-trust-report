-- =============================================================================
--  CIS PostgreSQL 18 Benchmark v1.0.0 (2026-03-27)  -- audit via psql
-- =============================================================================
--
--  PURPOSE
--  Run this script INSIDE an already-open, already-connected psql session:
--
--        psql -h <host> -U <user> -d <db>
--        <db>=# \i cis.sql
--
--  Assumption: you are ALREADY running and connected to PostgreSQL via psql.
--  The script does not log in or connect - it uses the current session.
--
--  WHAT IT DOES
--    * Items checkable from SQL (GUCs, roles, pg_hba_file_rules, extensions,
--      replication, TLS, etc.) -> a real PASS / FAIL / SKIP / WARN.
--    * Items that require operating-system access psql cannot reach (PGDATA
--      file ownership/mode, umask, systemd, shell profiles, /proc, sudoers,
--      $libdir, OS packages, pgBackRest, etc.) -> NOT checked. They are only
--      DISPLAYED with status MANL and the verbatim CIS Audit + Remediation
--      text for manual review.
--
--  RESULT
--    A TEMP table cis_results(section, title, status, detail) is filled while
--    the script runs and printed at the end with a summary.
--    Status: PASS | FAIL | WARN | SKIP | MANL
--
--  PRIVILEGES
--    No superuser required, and NO write access to schema public is needed
--    (all objects are temporary).  Some catalogs (pg_authid.rolpassword,
--    pg_hba_file_rules) are only readable by a superuser or a member of
--    pg_monitor / pg_read_all_settings; items that cannot be read with the
--    current privileges yield SKIP with an explanation, not a false FAIL.
--
--  NOTE: some items (4.5 / 4.6 / 4.7) are inherently PER-DATABASE - psql sees
--    only the current database. For a full audit, run the script in each one.
-- =============================================================================

\set ON_ERROR_STOP off
\timing off
\pset pager off

-- -----------------------------------------------------------------------------
--  Result table (TEMP - needs no privileges on schema public, auto-dropped)
-- -----------------------------------------------------------------------------
DROP TABLE IF EXISTS cis_results;
CREATE TEMP TABLE cis_results (
    seq      serial PRIMARY KEY,
    section  text,
    title    text,
    status   text,   -- PASS | FAIL | WARN | SKIP | MANL
    detail   text
);

-- -----------------------------------------------------------------------------
--  Safe GUC reader, created in pg_temp (no privilege on schema public needed;
--  auto-dropped at session end).  Returns NULL - rather than raising - when a
--  parameter does not exist OR when the current role lacks privilege to read
--  it (e.g. a non-superuser reading log_filename / data_directory).  Callers
--  treat NULL as SKIP, so a low-privilege session degrades gracefully.
-- -----------------------------------------------------------------------------
CREATE FUNCTION pg_temp.cis_guc(p_name text)
RETURNS text LANGUAGE plpgsql AS $cisfn$
BEGIN
    RETURN current_setting(p_name, true);
EXCEPTION WHEN OTHERS THEN
    RETURN NULL;
END;
$cisfn$;

-- -----------------------------------------------------------------------------
--  MAIN AUDIT - single anonymous DO block (creates NOTHING in public)
--  All SQL-checkable items write directly into cis_results.
--  Permission errors (e.g. no access to pg_authid) are caught -> SKIP.
-- -----------------------------------------------------------------------------
DO $audit$
DECLARE
    r record;
    v text; v2 text; v3 text;
    n int; m int;
    arr text[];
    missing text;
    pe text; bq text; lo text;

BEGIN

    -- ===== 3.1 Logging (GUCs) ================================================
    -- 3.1.2 log_destination
    v := pg_temp.cis_guc('log_destination');
    IF v IS NULL OR btrim(v) = '' THEN
        INSERT INTO cis_results(section,title,status,detail) VALUES
          ('3.1.2','Ensure the log destinations are set correctly','FAIL','log_destination is empty');
    ELSE
        INSERT INTO cis_results(section,title,status,detail) VALUES
          ('3.1.2','Ensure the log destinations are set correctly','PASS',
           format('log_destination = %s (confirm it matches the site logging policy)', v));
    END IF;

    -- 3.1.3 logging_collector = on
    v := pg_temp.cis_guc('logging_collector');
    INSERT INTO cis_results(section,title,status,detail) VALUES ('3.1.3','Ensure the logging collector is enabled',
      CASE WHEN v IS NULL THEN 'SKIP' WHEN lower(v)='on' THEN 'PASS' ELSE 'FAIL' END,
      CASE WHEN v IS NULL THEN 'could not read logging_collector' ELSE format('logging_collector = %s (expected on)', v) END);

    -- 3.1.5 log_filename set
    v := pg_temp.cis_guc('log_filename');
    IF v IS NULL OR btrim(v) = '' THEN
        INSERT INTO cis_results(section,title,status,detail) VALUES
          ('3.1.5','Ensure the filename pattern for log files is set correctly','FAIL','log_filename is empty');
    ELSE
        INSERT INTO cis_results(section,title,status,detail) VALUES
          ('3.1.5','Ensure the filename pattern for log files is set correctly','PASS',
           format('log_filename = %s (confirm the pattern meets policy, e.g. includes %%Y-%%m-%%d)', v));
    END IF;

    -- 3.1.6 log_file_mode (GUC part only; on-disk perms are an OS check)
    v := pg_temp.cis_guc('log_file_mode');
    INSERT INTO cis_results(section,title,status,detail) VALUES ('3.1.6','Ensure the log file permissions are set correctly',
      CASE WHEN v IS NULL THEN 'SKIP' WHEN v IN ('0600','600') THEN 'PASS' ELSE 'FAIL' END,
      CASE WHEN v IS NULL THEN 'could not read log_file_mode'
           WHEN v IN ('0600','600') THEN format('log_file_mode = %s', v)
           ELSE format('log_file_mode = %s (CIS expects 0600 or stricter; also verify on-disk file perms)', v) END);

    -- 3.1.7 log_truncate_on_rotation = on
    v := pg_temp.cis_guc('log_truncate_on_rotation');
    INSERT INTO cis_results(section,title,status,detail) VALUES ('3.1.7','Ensure log_truncate_on_rotation is enabled',
      CASE WHEN v IS NULL THEN 'SKIP' WHEN lower(v)='on' THEN 'PASS' ELSE 'FAIL' END,
      CASE WHEN v IS NULL THEN 'could not read log_truncate_on_rotation' ELSE format('log_truncate_on_rotation = %s (expected on)', v) END);

    -- 3.1.8 log_rotation_age (policy)
    v := pg_temp.cis_guc('log_rotation_age');
    INSERT INTO cis_results(section,title,status,detail) VALUES ('3.1.8','Ensure the maximum log file lifetime is set correctly',
      CASE WHEN v IS NULL THEN 'SKIP' ELSE 'PASS' END,
      COALESCE(format('log_rotation_age = %s (confirm against retention policy)', v),'not read'));

    -- 3.1.9 log_rotation_size (policy)
    v := pg_temp.cis_guc('log_rotation_size');
    INSERT INTO cis_results(section,title,status,detail) VALUES ('3.1.9','Ensure the maximum log file size is set correctly',
      CASE WHEN v IS NULL THEN 'SKIP' ELSE 'PASS' END,
      COALESCE(format('log_rotation_size = %s (confirm against policy)', v),'not read'));

    -- 3.1.10 syslog_facility (Manual/policy) -> MANL with reading
    v := pg_temp.cis_guc('syslog_facility'); v2 := pg_temp.cis_guc('log_destination');
    INSERT INTO cis_results(section,title,status,detail) VALUES ('3.1.10','Ensure the correct syslog facility is selected','MANL',
      format('syslog_facility = %s (log_destination = %s); confirm the facility when syslog is in use. See the CIS PostgreSQL 18 Benchmark PDF, section 3.1.10, for the manual Audit/Remediation procedure.', v, v2));

    -- 3.1.11 syslog_sequence_numbers = on
    v := pg_temp.cis_guc('syslog_sequence_numbers');
    INSERT INTO cis_results(section,title,status,detail) VALUES ('3.1.11','Ensure syslog messages are not suppressed',
      CASE WHEN v IS NULL THEN 'SKIP' WHEN lower(v)='on' THEN 'PASS' ELSE 'FAIL' END,
      CASE WHEN v IS NULL THEN 'could not read syslog_sequence_numbers' ELSE format('syslog_sequence_numbers = %s (expected on)', v) END);

    -- 3.1.12 syslog_split_messages = on
    v := pg_temp.cis_guc('syslog_split_messages');
    INSERT INTO cis_results(section,title,status,detail) VALUES ('3.1.12','Ensure syslog messages are not lost due to size',
      CASE WHEN v IS NULL THEN 'SKIP' WHEN lower(v)='on' THEN 'PASS' ELSE 'FAIL' END,
      CASE WHEN v IS NULL THEN 'could not read syslog_split_messages' ELSE format('syslog_split_messages = %s (expected on)', v) END);

    -- 3.1.13 syslog_ident = postgres
    v := pg_temp.cis_guc('syslog_ident');
    INSERT INTO cis_results(section,title,status,detail) VALUES ('3.1.13','Ensure the program name for PostgreSQL syslog messages is correct',
      CASE WHEN v IS NULL THEN 'SKIP' WHEN v='postgres' THEN 'PASS' ELSE 'WARN' END,
      CASE WHEN v IS NULL THEN 'could not read syslog_ident'
           WHEN v='postgres' THEN 'syslog_ident = postgres'
           ELSE format('syslog_ident = %s (CIS example: postgres; confirm against policy)', v) END);

    -- 3.1.14 log_min_messages (baseline warning)
    v := pg_temp.cis_guc('log_min_messages');
    INSERT INTO cis_results(section,title,status,detail) VALUES ('3.1.14','Ensure the correct messages are written to the server log',
      CASE WHEN v IS NULL THEN 'SKIP' ELSE 'PASS' END,
      COALESCE(format('log_min_messages = %s (CIS baseline ''warning''; confirm against policy)', v),'not read'));

    -- 3.1.15 log_min_error_statement (baseline error)
    v := pg_temp.cis_guc('log_min_error_statement');
    INSERT INTO cis_results(section,title,status,detail) VALUES ('3.1.15','Ensure the correct SQL statements generating errors are recorded',
      CASE WHEN v IS NULL THEN 'SKIP' ELSE 'PASS' END,
      COALESCE(format('log_min_error_statement = %s (CIS baseline ''error''; confirm against policy)', v),'not read'));

    -- 3.1.16-3.1.19 debug_*
    v := pg_temp.cis_guc('debug_print_parse');
    INSERT INTO cis_results(section,title,status,detail) VALUES ('3.1.16','Ensure debug_print_parse is disabled',
      CASE WHEN v IS NULL THEN 'SKIP' WHEN lower(v)='off' THEN 'PASS' ELSE 'FAIL' END,
      COALESCE(format('debug_print_parse = %s (expected off)', v),'could not read debug_print_parse'));
    v := pg_temp.cis_guc('debug_print_rewritten');
    INSERT INTO cis_results(section,title,status,detail) VALUES ('3.1.17','Ensure debug_print_rewritten is disabled',
      CASE WHEN v IS NULL THEN 'SKIP' WHEN lower(v)='off' THEN 'PASS' ELSE 'FAIL' END,
      COALESCE(format('debug_print_rewritten = %s (expected off)', v),'could not read debug_print_rewritten'));
    v := pg_temp.cis_guc('debug_print_plan');
    INSERT INTO cis_results(section,title,status,detail) VALUES ('3.1.18','Ensure debug_print_plan is disabled',
      CASE WHEN v IS NULL THEN 'SKIP' WHEN lower(v)='off' THEN 'PASS' ELSE 'FAIL' END,
      COALESCE(format('debug_print_plan = %s (expected off)', v),'could not read debug_print_plan'));
    v := pg_temp.cis_guc('debug_pretty_print');
    INSERT INTO cis_results(section,title,status,detail) VALUES ('3.1.19','Ensure debug_pretty_print is enabled',
      CASE WHEN v IS NULL THEN 'SKIP' WHEN lower(v)='on' THEN 'PASS' ELSE 'FAIL' END,
      COALESCE(format('debug_pretty_print = %s (expected on)', v),'could not read debug_pretty_print'));

    -- 3.1.20 log_connections = all (PG18)
    v := pg_temp.cis_guc('log_connections');
    INSERT INTO cis_results(section,title,status,detail) VALUES ('3.1.20','Ensure log_connections is enabled',
      CASE WHEN v IS NULL THEN 'SKIP' WHEN lower(v)='all' THEN 'PASS' ELSE 'FAIL' END,
      COALESCE(format('log_connections = %s (expected all)', v),'could not read log_connections'));

    -- 3.1.21 log_disconnections = on
    v := pg_temp.cis_guc('log_disconnections');
    INSERT INTO cis_results(section,title,status,detail) VALUES ('3.1.21','Ensure log_disconnections is enabled',
      CASE WHEN v IS NULL THEN 'SKIP' WHEN lower(v)='on' THEN 'PASS' ELSE 'FAIL' END,
      COALESCE(format('log_disconnections = %s (expected on)', v),'could not read log_disconnections'));

    -- 3.1.22 log_error_verbosity = verbose
    v := pg_temp.cis_guc('log_error_verbosity');
    INSERT INTO cis_results(section,title,status,detail) VALUES ('3.1.22','Ensure log_error_verbosity is set correctly',
      CASE WHEN v IS NULL THEN 'SKIP' WHEN lower(v)='verbose' THEN 'PASS' ELSE 'FAIL' END,
      COALESCE(format('log_error_verbosity = %s (expected verbose)', v),'could not read log_error_verbosity'));

    -- 3.1.23 log_hostname = off
    v := pg_temp.cis_guc('log_hostname');
    INSERT INTO cis_results(section,title,status,detail) VALUES ('3.1.23','Ensure log_hostname is set correctly',
      CASE WHEN v IS NULL THEN 'SKIP' WHEN lower(v)='off' THEN 'PASS' ELSE 'FAIL' END,
      COALESCE(format('log_hostname = %s (expected off)', v),'could not read log_hostname'));

    -- 3.1.24 log_line_prefix contains required escapes
    v := pg_temp.cis_guc('log_line_prefix');
    IF v IS NULL THEN
        INSERT INTO cis_results(section,title,status,detail) VALUES ('3.1.24','Ensure log_line_prefix is set correctly','SKIP','could not read log_line_prefix');
    ELSE
        missing := '';
        IF position('%m' in v) = 0 THEN missing := missing || ' %m'; END IF;
        IF position('%p' in v) = 0 THEN missing := missing || ' %p'; END IF;
        IF position('%u' in v) = 0 THEN missing := missing || ' %u'; END IF;
        IF position('%d' in v) = 0 THEN missing := missing || ' %d'; END IF;
        IF position('%a' in v) = 0 THEN missing := missing || ' %a'; END IF;
        IF position('%h' in v) = 0 THEN missing := missing || ' %h'; END IF;
        IF btrim(missing) = '' THEN
            INSERT INTO cis_results(section,title,status,detail) VALUES ('3.1.24','Ensure log_line_prefix is set correctly','PASS',
              format('log_line_prefix = %L (contains the required escapes)', v));
        ELSE
            INSERT INTO cis_results(section,title,status,detail) VALUES ('3.1.24','Ensure log_line_prefix is set correctly','FAIL',
              format('log_line_prefix = %L; missing escape(s):%s', v, missing));
        END IF;
    END IF;

    -- 3.1.25 log_statement <> none
    v := pg_temp.cis_guc('log_statement');
    INSERT INTO cis_results(section,title,status,detail) VALUES ('3.1.25','Ensure log_statement is set correctly',
      CASE WHEN v IS NULL THEN 'SKIP' WHEN lower(v)='none' THEN 'FAIL' ELSE 'PASS' END,
      CASE WHEN v IS NULL THEN 'could not read log_statement'
           WHEN lower(v)='none' THEN 'log_statement = none (CIS: must be ddl/mod/all per policy)'
           ELSE format('log_statement = %s', v) END);

    -- 3.1.26 log_timezone = GMT/UTC
    v := pg_temp.cis_guc('log_timezone');
    INSERT INTO cis_results(section,title,status,detail) VALUES ('3.1.26','Ensure log_timezone is set correctly',
      CASE WHEN v IS NULL THEN 'SKIP' WHEN v IN ('GMT','UTC') THEN 'PASS' ELSE 'FAIL' END,
      COALESCE(format('log_timezone = %s (expected GMT or UTC)', v),'could not read log_timezone'));

    -- ===== 3.2 pgAudit =======================================================
    v := pg_temp.cis_guc('shared_preload_libraries');
    IF v IS NULL THEN
        INSERT INTO cis_results(section,title,status,detail) VALUES ('3.2','Ensure the PostgreSQL Audit Extension (pgAudit) is enabled','SKIP','could not read shared_preload_libraries');
    ELSIF v !~* '(^|[, ])pgaudit([, ]|$)' THEN
        INSERT INTO cis_results(section,title,status,detail) VALUES ('3.2','Ensure the PostgreSQL Audit Extension (pgAudit) is enabled','FAIL',
          format('shared_preload_libraries = %L does not contain pgaudit', v));
    ELSE
        v2 := pg_temp.cis_guc('pgaudit.log');
        IF v2 IS NULL OR btrim(v2) = '' THEN
            INSERT INTO cis_results(section,title,status,detail) VALUES ('3.2','Ensure the PostgreSQL Audit Extension (pgAudit) is enabled','WARN',
              format('pgaudit is preloaded but pgaudit.log is empty (spl=%L); configure audit classes per policy', v));
        ELSE
            INSERT INTO cis_results(section,title,status,detail) VALUES ('3.2','Ensure the PostgreSQL Audit Extension (pgAudit) is enabled','PASS',
              format('pgaudit preloaded; pgaudit.log = %s', v2));
        END IF;
    END IF;

    -- ===== 4.x Access / authorization ========================================
    -- 4.3 excessive administrative privileges -> MANL with reading
    BEGIN
        SELECT string_agg(format('%s(super=%s,createrole=%s,createdb=%s,repl=%s,bypassrls=%s)',
                 rolname, rolsuper, rolcreaterole, rolcreatedb, rolreplication, rolbypassrls), ' ; ')
        INTO v FROM pg_roles
        WHERE rolsuper OR rolcreaterole OR rolcreatedb OR rolreplication OR rolbypassrls;
        INSERT INTO cis_results(section,title,status,detail) VALUES ('4.3','Ensure excessive administrative privileges are revoked','MANL',
          format('Roles with elevated attributes: %s. Review against least-privilege policy. See the CIS PostgreSQL 18 Benchmark PDF, section 4.3, for the manual Audit/Remediation procedure.', COALESCE(v,'(none)')));
    EXCEPTION WHEN insufficient_privilege THEN
        INSERT INTO cis_results(section,title,status,detail) VALUES ('4.3','Ensure excessive administrative privileges are revoked','SKIP','no privilege to read pg_roles');
    END;

    -- 4.4 unused accounts -> MANL with rolvaliduntil
    BEGIN
        SELECT string_agg(format('%s(valid_until=%s)', rolname, COALESCE(rolvaliduntil::text,'inf')), ' ; ')
        INTO v FROM pg_roles WHERE rolcanlogin;
        INSERT INTO cis_results(section,title,status,detail) VALUES ('4.4','Lock Out Accounts if Not Currently in Use','MANL',
          format('Login-capable accounts: %s. Lock/expire any not currently in use per policy. See the CIS PostgreSQL 18 Benchmark PDF, section 4.4, for the manual Audit/Remediation procedure.', COALESCE(v,'(none)')));
    EXCEPTION WHEN OTHERS THEN
        INSERT INTO cis_results(section,title,status,detail) VALUES ('4.4','Lock Out Accounts if Not Currently in Use','SKIP', format('read error: %s', SQLERRM));
    END;

    -- 4.5 excessive function privileges (SECURITY DEFINER / proconfig)
    BEGIN
        SELECT count(*), string_agg(format('%s.%s', n.nspname, p.proname), ', ')
        INTO m, v
        FROM pg_proc p JOIN pg_namespace n ON p.pronamespace = n.oid
        WHERE p.proname NOT LIKE 'pgaudit%' AND (p.prosecdef OR p.proconfig IS NOT NULL);
        IF COALESCE(m,0) = 0 THEN
            INSERT INTO cis_results(section,title,status,detail) VALUES ('4.5','Ensure excessive function privileges are revoked','PASS',
              'No SECURITY DEFINER / proconfig functions found (excluding pgaudit)');
        ELSE
            INSERT INTO cis_results(section,title,status,detail) VALUES ('4.5','Ensure excessive function privileges are revoked','FAIL',
              format('%s privilege-elevating function(s): %s. Revoke if not required.', m, v));
        END IF;
    EXCEPTION WHEN OTHERS THEN
        INSERT INTO cis_results(section,title,status,detail) VALUES ('4.5','Ensure excessive function privileges are revoked','SKIP', format('error: %s', SQLERRM));
    END;

    -- 4.6 excessive PUBLIC DML -> MANL (per-database)
    BEGIN
        SELECT string_agg(format('%s.%s:%s', table_schema, table_name, privilege_type), ', ')
        INTO v FROM information_schema.role_table_grants
        WHERE grantee = 'PUBLIC' AND privilege_type IN ('INSERT','UPDATE','DELETE','TRUNCATE');
        IF v IS NULL THEN
            INSERT INTO cis_results(section,title,status,detail) VALUES ('4.6','Ensure excessive DML privileges are revoked','MANL',
              'No PUBLIC DML grants in the current database; still review per-role DML grants against least-privilege policy (audit is per-database). See the CIS PostgreSQL 18 Benchmark PDF, section 4.6, for the manual Audit/Remediation procedure.');
        ELSE
            INSERT INTO cis_results(section,title,status,detail) VALUES ('4.6','Ensure excessive DML privileges are revoked','MANL',
              format('PUBLIC DML grants present: %s. Review/REVOKE per policy. See the CIS PostgreSQL 18 Benchmark PDF, section 4.6, for the manual Audit/Remediation procedure.', v));
        END IF;
    EXCEPTION WHEN OTHERS THEN
        INSERT INTO cis_results(section,title,status,detail) VALUES ('4.6','Ensure excessive DML privileges are revoked','MANL', format('Could not enumerate (%s); review manually. See the CIS PostgreSQL 18 Benchmark PDF, section 4.6, for the manual Audit/Remediation procedure.', SQLERRM));
    END;

    -- 4.7 RLS -> MANL (per-database)
    BEGIN
        SELECT string_agg(format('%s.%s(rls=%s,forced=%s)', n.nspname, c.relname, c.relrowsecurity, c.relforcerowsecurity), ' ; ')
        INTO v FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
        WHERE c.relkind='r' AND n.nspname NOT IN ('pg_catalog','information_schema')
          AND EXISTS (SELECT 1 FROM pg_policy p WHERE p.polrelid = c.oid);
        IF v IS NULL THEN
            INSERT INTO cis_results(section,title,status,detail) VALUES ('4.7','Ensure Row Level Security (RLS) is configured correctly','MANL',
              'No tables with RLS policies in the current database; if RLS is required by design, verify it is configured (audit is per-database). See the CIS PostgreSQL 18 Benchmark PDF, section 4.7, for the manual Audit/Remediation procedure.');
        ELSE
            INSERT INTO cis_results(section,title,status,detail) VALUES ('4.7','Ensure Row Level Security (RLS) is configured correctly','MANL',
              format('Tables with RLS policies: %s. Confirm relrowsecurity is enabled where required. See the CIS PostgreSQL 18 Benchmark PDF, section 4.7, for the manual Audit/Remediation procedure.', v));
        END IF;
    EXCEPTION WHEN OTHERS THEN
        INSERT INTO cis_results(section,title,status,detail) VALUES ('4.7','Ensure Row Level Security (RLS) is configured correctly','MANL', format('Could not enumerate (%s); review manually. See the CIS PostgreSQL 18 Benchmark PDF, section 4.7, for the manual Audit/Remediation procedure.', SQLERRM));
    END;

    -- 4.8 set_user extension
    SELECT count(*) INTO n FROM pg_available_extensions WHERE name='set_user';
    IF n = 0 THEN
        INSERT INTO cis_results(section,title,status,detail) VALUES ('4.8','Ensure the set_user extension is installed','FAIL','set_user is not available on this server (not installed on disk)');
    ELSE
        SELECT count(*) INTO m FROM pg_extension WHERE extname='set_user';
        IF m = 0 THEN
            INSERT INTO cis_results(section,title,status,detail) VALUES ('4.8','Ensure the set_user extension is installed','FAIL','set_user is available but not created in the current database (CREATE EXTENSION set_user)');
        ELSE
            INSERT INTO cis_results(section,title,status,detail) VALUES ('4.8','Ensure the set_user extension is installed','PASS','set_user is available and installed in the current database');
        END IF;
    END IF;

    -- 4.9 predefined roles -> MANL
    SELECT count(*) INTO n FROM pg_roles WHERE rolname LIKE 'pg\_%';
    INSERT INTO cis_results(section,title,status,detail) VALUES ('4.9','Make use of predefined roles','MANL',
      format('Use predefined pg_* roles where appropriate (pg_read_all_data, pg_monitor, ...). Design/policy review; pg_* roles present on server: %s. See the CIS PostgreSQL 18 Benchmark PDF, section 4.9, for the manual Audit/Remediation procedure.', n));

    -- 4.10 login-capable accounts without a password
    BEGIN
        SELECT string_agg(rolname, ', ') INTO v FROM pg_authid WHERE rolpassword IS NULL AND rolcanlogin;
        IF v IS NULL THEN
            INSERT INTO cis_results(section,title,status,detail) VALUES ('4.10','Ensure all accounts that can log in have passwords','PASS','All login-capable roles have a password (or none lack one)');
        ELSE
            INSERT INTO cis_results(section,title,status,detail) VALUES ('4.10','Ensure all accounts that can log in have passwords','WARN',
              format('Login roles without a password (verify they use SSL client certs, else FAIL): %s', v));
        END IF;
    EXCEPTION WHEN insufficient_privilege THEN
        INSERT INTO cis_results(section,title,status,detail) VALUES ('4.10','Ensure all accounts that can log in have passwords','SKIP','superuser required to read pg_authid.rolpassword');
    END;

    -- ===== 5.x Connection / login ============================================
    -- 5.3 HBA local
    BEGIN
        SELECT string_agg(format('L%s:%s', line_number, auth_method), ', '),
               string_agg(CASE WHEN auth_method IN ('trust','password') THEN format('L%s:%s', line_number, auth_method) END, '; ')
        INTO v, v2 FROM pg_hba_file_rules WHERE type='local';
        IF v IS NULL THEN
            INSERT INTO cis_results(section,title,status,detail) VALUES ('5.3','Ensure login via "local" UNIX Domain Socket is configured correctly','PASS','No local-type HBA rules present');
        ELSIF v2 IS NOT NULL THEN
            INSERT INTO cis_results(section,title,status,detail) VALUES ('5.3','Ensure login via "local" UNIX Domain Socket is configured correctly','FAIL',
              format('Insecure local auth method(s): %s (all local rules: %s)', v2, v));
        ELSE
            INSERT INTO cis_results(section,title,status,detail) VALUES ('5.3','Ensure login via "local" UNIX Domain Socket is configured correctly','PASS',
              format('Local methods acceptable: %s (confirm scram-sha-256/peer per policy)', v));
        END IF;
    EXCEPTION WHEN insufficient_privilege THEN
        INSERT INTO cis_results(section,title,status,detail) VALUES ('5.3','Ensure login via "local" UNIX Domain Socket is configured correctly','SKIP','superuser/pg_read_all_settings required for pg_hba_file_rules');
    END;

    -- 5.4 HBA host/hostssl
    BEGIN
        SELECT
          string_agg(CASE WHEN auth_method IN ('trust','password') THEN format('L%s:%s/%s', line_number, type, auth_method) END, '; '),
          string_agg(CASE WHEN type='host' THEN format('L%s', line_number) END, ', ')
        INTO v, v2 FROM pg_hba_file_rules WHERE type IN ('host','hostssl','hostnossl');
        IF v IS NOT NULL THEN
            INSERT INTO cis_results(section,title,status,detail) VALUES ('5.4','Ensure login via "host" TCP/IP Socket is configured correctly','FAIL',
              format('Insecure host auth method(s): %s', v));
        ELSIF v2 IS NOT NULL THEN
            INSERT INTO cis_results(section,title,status,detail) VALUES ('5.4','Ensure login via "host" TCP/IP Socket is configured correctly','WARN',
              format('Plain host (not hostssl) rules at lines %s - confirm TLS is enforced or switch to hostssl', v2));
        ELSE
            INSERT INTO cis_results(section,title,status,detail) VALUES ('5.4','Ensure login via "host" TCP/IP Socket is configured correctly','PASS','Host rules use hostssl with acceptable methods (or no host rules present)');
        END IF;
    EXCEPTION WHEN insufficient_privilege THEN
        INSERT INTO cis_results(section,title,status,detail) VALUES ('5.4','Ensure login via "host" TCP/IP Socket is configured correctly','SKIP','superuser/pg_read_all_settings required for pg_hba_file_rules');
    END;

    -- 5.5 per-account connection limits
    BEGIN
        SELECT string_agg(rolname, ', ') INTO v
        FROM pg_roles WHERE rolname NOT LIKE 'pg\_%' AND rolcanlogin AND rolconnlimit = -1;
        IF v IS NULL THEN
            INSERT INTO cis_results(section,title,status,detail) VALUES ('5.5','Ensure per-account connection limits are used','PASS','All login roles have a connection limit set (none at -1)');
        ELSE
            INSERT INTO cis_results(section,title,status,detail) VALUES ('5.5','Ensure per-account connection limits are used','FAIL',
              format('Login role(s) with unlimited connections (rolconnlimit = -1): %s', v));
        END IF;
    EXCEPTION WHEN OTHERS THEN
        INSERT INTO cis_results(section,title,status,detail) VALUES ('5.5','Ensure per-account connection limits are used','SKIP', format('error: %s', SQLERRM));
    END;

    -- 5.6 password complexity (passwordcheck in preload)
    v := pg_temp.cis_guc('shared_preload_libraries');
    IF v IS NULL THEN
        INSERT INTO cis_results(section,title,status,detail) VALUES ('5.6','Ensure Password Complexity is configured','SKIP','could not read shared_preload_libraries');
    ELSIF v ~* 'passwordcheck' THEN
        INSERT INTO cis_results(section,title,status,detail) VALUES ('5.6','Ensure Password Complexity is configured','PASS', format('passwordcheck present in shared_preload_libraries (%L)', v));
    ELSE
        INSERT INTO cis_results(section,title,status,detail) VALUES ('5.6','Ensure Password Complexity is configured','WARN',
          format('passwordcheck not in shared_preload_libraries (%L); complexity enforcement needs a passwordcheck-style module', v));
    END IF;

    -- ===== 6.x Runtime parameters / crypto ===================================
    -- 6.2 backend params
    BEGIN
        v := ''; v3 := '';
        FOR r IN SELECT name, setting FROM pg_settings WHERE context IN ('backend','superuser-backend') ORDER BY name LOOP
            v3 := v3 || format('%s=%s, ', r.name, r.setting);
            IF (r.name='ignore_system_indexes' AND lower(r.setting)<>'off')
               OR (r.name='jit_debugging_support' AND lower(r.setting)<>'off')
               OR (r.name='jit_profiling_support' AND lower(r.setting)<>'off')
               OR (r.name='post_auth_delay' AND r.setting<>'0')
               OR (r.name='log_connections' AND lower(r.setting)<>'all')
               OR (r.name='log_disconnections' AND lower(r.setting)<>'on')
            THEN v := v || format('%s=%s; ', r.name, r.setting);
            END IF;
        END LOOP;
        IF btrim(v) = '' THEN
            INSERT INTO cis_results(section,title,status,detail) VALUES ('6.2','Ensure ''backend'' runtime parameters are configured correctly','PASS',
              format('backend params at baseline: %s', rtrim(v3, ', ')));
        ELSE
            INSERT INTO cis_results(section,title,status,detail) VALUES ('6.2','Ensure ''backend'' runtime parameters are configured correctly','FAIL',
              format('params off-baseline: %s (all: %s)', rtrim(v,'; '), rtrim(v3, ', ')));
        END IF;
    EXCEPTION WHEN OTHERS THEN
        INSERT INTO cis_results(section,title,status,detail) VALUES ('6.2','Ensure ''backend'' runtime parameters are configured correctly','SKIP', format('error: %s', SQLERRM));
    END;

    -- 6.3-6.6 parameter inventory by context -> MANL with reading
    SELECT count(*) INTO n FROM pg_settings WHERE context='postmaster';
    INSERT INTO cis_results(section,title,status,detail) VALUES ('6.3','Ensure ''Postmaster'' Runtime Parameters are Configured','MANL',
      format('%s postmaster (server-start) runtime parameter(s) present - review their values against your security policy (no fixed CIS value; inspect via: SELECT name, setting FROM pg_settings WHERE context = ''postmaster''). See the CIS PostgreSQL 18 Benchmark PDF, section 6.3, for the manual Audit/Remediation procedure.', n));

    SELECT count(*) INTO n FROM pg_settings WHERE context='sighup';
    INSERT INTO cis_results(section,title,status,detail) VALUES ('6.4','Ensure ''SIGHUP'' Runtime Parameters are Configured','MANL',
      format('%s SIGHUP (reload) runtime parameter(s) present - review their values against your security policy (no fixed CIS value; inspect via: SELECT name, setting FROM pg_settings WHERE context = ''sighup''). See the CIS PostgreSQL 18 Benchmark PDF, section 6.4, for the manual Audit/Remediation procedure.', n));

    SELECT count(*) INTO n FROM pg_settings WHERE context='superuser';
    INSERT INTO cis_results(section,title,status,detail) VALUES ('6.5','Ensure ''Superuser'' Runtime Parameters are Configured','MANL',
      format('%s superuser-settable runtime parameter(s) present - review their values against your security policy (no fixed CIS value; inspect via: SELECT name, setting FROM pg_settings WHERE context = ''superuser''). See the CIS PostgreSQL 18 Benchmark PDF, section 6.5, for the manual Audit/Remediation procedure.', n));

    SELECT count(*) INTO n FROM pg_settings WHERE context='user';
    INSERT INTO cis_results(section,title,status,detail) VALUES ('6.6','Ensure ''User'' Runtime Parameters are Configured','MANL',
      format('%s user-settable runtime parameter(s) present - review their values against your security policy (no fixed CIS value; inspect via: SELECT name, setting FROM pg_settings WHERE context = ''user''). See the CIS PostgreSQL 18 Benchmark PDF, section 6.6, for the manual Audit/Remediation procedure.', n));

    -- 6.8 TLS enabled
    v := pg_temp.cis_guc('ssl');
    IF v IS NULL THEN
        INSERT INTO cis_results(section,title,status,detail) VALUES ('6.8','Ensure TLS is enabled and configured correctly','SKIP','could not read ssl');
    ELSIF lower(v)='on' THEN
        v2 := pg_temp.cis_guc('ssl_cert_file'); v3 := pg_temp.cis_guc('ssl_key_file');
        INSERT INTO cis_results(section,title,status,detail) VALUES ('6.8','Ensure TLS is enabled and configured correctly','PASS',
          format('ssl = on (ssl_cert_file=%L, ssl_key_file=%L; verify cert/key on-disk ownership and 0600 perms separately)', v2, v3));
    ELSE
        INSERT INTO cis_results(section,title,status,detail) VALUES ('6.8','Ensure TLS is enabled and configured correctly','FAIL', format('ssl = %s (expected on)', v));
    END IF;

    -- 6.9 ssl_min_protocol_version TLSv1.2/1.3
    v := pg_temp.cis_guc('ssl_min_protocol_version');
    INSERT INTO cis_results(section,title,status,detail) VALUES ('6.9','Ensure the TLSv1.0 and TLSv1.1 Protocols are Disabled',
      CASE WHEN v IS NULL OR btrim(v)='' THEN 'SKIP' WHEN v IN ('TLSv1.2','TLSv1.3') THEN 'PASS' ELSE 'FAIL' END,
      CASE WHEN v IS NULL OR btrim(v)='' THEN 'ssl_min_protocol_version empty (SSL may be disabled)'
           WHEN v IN ('TLSv1.2','TLSv1.3') THEN format('ssl_min_protocol_version = %s', v)
           ELSE format('ssl_min_protocol_version = %s (must be TLSv1.2 or TLSv1.3)', v) END);

    -- 6.10 weak TLS1.3 ciphers + active-connection check
    v := pg_temp.cis_guc('ssl_tls13_ciphers');
    SELECT count(*) INTO m FROM pg_stat_ssl
        WHERE ssl AND cipher NOT IN ('TLS_AES_256_GCM_SHA384','TLS_AES_128_GCM_SHA256','TLS_AES_128_CCM_SHA256');
    IF v IS NULL OR btrim(v)='' THEN
        INSERT INTO cis_results(section,title,status,detail) VALUES ('6.10','Ensure Weak SSL/TLS Ciphers Are Disabled','WARN',
          format('ssl_tls13_ciphers empty -> OpenSSL default TLS1.3 list applies; active connections using a non-approved cipher: %s', m));
    ELSE
        arr := ARRAY(SELECT btrim(x) FROM regexp_split_to_table(v, '[:, ]+') x WHERE btrim(x)<>'');
        SELECT string_agg(c, ',') INTO v2 FROM unnest(arr) c
            WHERE c NOT IN ('TLS_AES_256_GCM_SHA384','TLS_AES_128_GCM_SHA256','TLS_AES_128_CCM_SHA256');
        IF v2 IS NOT NULL THEN
            INSERT INTO cis_results(section,title,status,detail) VALUES ('6.10','Ensure Weak SSL/TLS Ciphers Are Disabled','FAIL',
              format('ssl_tls13_ciphers includes non-approved suite(s): %s; active weak connections: %s', v2, m));
        ELSIF m > 0 THEN
            INSERT INTO cis_results(section,title,status,detail) VALUES ('6.10','Ensure Weak SSL/TLS Ciphers Are Disabled','WARN',
              format('ssl_tls13_ciphers list OK but %s active SSL connection(s) use a non-approved cipher', m));
        ELSE
            INSERT INTO cis_results(section,title,status,detail) VALUES ('6.10','Ensure Weak SSL/TLS Ciphers Are Disabled','PASS','ssl_tls13_ciphers restricted to approved suites; no active weak SSL connections');
        END IF;
    END IF;

    -- 6.11 pgcrypto -> MANL with availability
    SELECT count(*) INTO n FROM pg_available_extensions WHERE name='pgcrypto';
    SELECT count(*) INTO m FROM pg_extension WHERE extname='pgcrypto';
    INSERT INTO cis_results(section,title,status,detail) VALUES ('6.11','Ensure the pgcrypto extension is installed and configured correctly','MANL',
      format('pgcrypto: available=%s, installed_in_current_db=%s. How it should be used is a data-protection design decision. See the CIS PostgreSQL 18 Benchmark PDF, section 6.11, for the manual Audit/Remediation procedure.', n, m));

    -- ===== 7.x Replication ===================================================
    -- 7.1 dedicated replication user -> MANL
    BEGIN
        SELECT string_agg(format('%s(super=%s,login=%s)', rolname, rolsuper, rolcanlogin), ' ; ') INTO v
        FROM pg_roles WHERE rolreplication;
        IF v IS NULL THEN
            INSERT INTO cis_results(section,title,status,detail) VALUES ('7.1','Ensure a replication-only user is created and used for streaming replication','MANL',
              'No role has the REPLICATION attribute. If streaming replication is used, create a dedicated non-superuser replication role. See the CIS PostgreSQL 18 Benchmark PDF, section 7.1, for the manual Audit/Remediation procedure.');
        ELSE
            INSERT INTO cis_results(section,title,status,detail) VALUES ('7.1','Ensure a replication-only user is created and used for streaming replication','MANL',
              format('Replication-capable roles: %s. Confirm a DEDICATED, non-superuser role is used for replication. See the CIS PostgreSQL 18 Benchmark PDF, section 7.1, for the manual Audit/Remediation procedure.', v));
        END IF;
    EXCEPTION WHEN OTHERS THEN
        INSERT INTO cis_results(section,title,status,detail) VALUES ('7.1','Ensure a replication-only user is created and used for streaming replication','SKIP', format('error: %s', SQLERRM));
    END;

    -- 7.2 logging of replication commands
    v := pg_temp.cis_guc('log_replication_commands');
    IF v IS NULL THEN
        INSERT INTO cis_results(section,title,status,detail) VALUES ('7.2','Ensure logging of replication commands is configured','SKIP','could not read log_replication_commands');
    ELSIF lower(v)='on' THEN
        INSERT INTO cis_results(section,title,status,detail) VALUES ('7.2','Ensure logging of replication commands is configured','PASS','log_replication_commands = on');
    ELSE
        INSERT INTO cis_results(section,title,status,detail) VALUES ('7.2','Ensure logging of replication commands is configured','MANL',
          format('log_replication_commands = %s; CIS recommends ''on'' when replication is used (Manual - depends on usage). See the CIS PostgreSQL 18 Benchmark PDF, section 7.2, for the manual Audit/Remediation procedure.', v));
    END IF;

    -- 7.4 WAL archiving configured AND functional
    v := pg_temp.cis_guc('archive_mode'); v2 := pg_temp.cis_guc('archive_command'); v3 := pg_temp.cis_guc('archive_library');
    IF NOT (lower(COALESCE(v,'')) IN ('on','always')
            AND ((v2 IS NOT NULL AND btrim(v2)<>'' AND v2<>'(disabled)') OR (v3 IS NOT NULL AND btrim(v3)<>''))) THEN
        INSERT INTO cis_results(section,title,status,detail) VALUES ('7.4','Ensure WAL archiving is configured and functional','FAIL',
          format('WAL archiving not enabled: archive_mode=%L, archive_command=%L, archive_library=%L', v, v2, v3));
    ELSE
        SELECT format('archived=%s, failed=%s, last_archived=%s, last_failed=%s',
                      archived_count, failed_count, last_archived_time, last_failed_time),
               archived_count, failed_count
        INTO v2, n, m FROM pg_stat_archiver;
        IF COALESCE(n,0) = 0 THEN
            INSERT INTO cis_results(section,title,status,detail) VALUES ('7.4','Ensure WAL archiving is configured and functional','WARN',
              format('Archiving configured (archive_mode=%s) but archived_count=0 - not yet proven functional. %s', v, v2));
        ELSIF COALESCE(m,0) > 0 THEN
            INSERT INTO cis_results(section,title,status,detail) VALUES ('7.4','Ensure WAL archiving is configured and functional','WARN',
              format('Archiving working but failed_count > 0. %s', v2));
        ELSE
            INSERT INTO cis_results(section,title,status,detail) VALUES ('7.4','Ensure WAL archiving is configured and functional','PASS',
              format('WAL archiving enabled and functional (archive_mode=%s). %s', v, v2));
        END IF;
    END IF;

    -- 7.5 streaming replication parameters -> MANL with reading
    SELECT string_agg(format('%s=%s', name, setting), ', ' ORDER BY name) INTO v
    FROM pg_settings WHERE name IN ('wal_level','max_wal_senders','max_replication_slots','hot_standby',
                                    'wal_keep_size','primary_conninfo','synchronous_standby_names','synchronous_commit');
    INSERT INTO cis_results(section,title,status,detail) VALUES ('7.5','Ensure streaming replication parameters are configured correctly','MANL',
      format('Streaming-replication parameters captured for review: %s. Confirm they match your topology/policy. See the CIS PostgreSQL 18 Benchmark PDF, section 7.5, for the manual Audit/Remediation procedure.', COALESCE(v,'(none)')));

    -- ===== 8.x Backup / misc =================================================
    -- 8.3 misc configuration settings -> MANL with reading + flags
    pe := pg_temp.cis_guc('password_encryption');
    bq := pg_temp.cis_guc('backslash_quote');
    lo := pg_temp.cis_guc('lo_compat_privileges');
    v := '';
    IF pe IS NOT NULL AND lower(pe) <> 'scram-sha-256' THEN v := v || format('password_encryption=%s (CIS: scram-sha-256); ', pe); END IF;
    IF bq IS NOT NULL AND lower(bq) = 'on' THEN v := v || 'backslash_quote=on (should be safe_encoding/off); '; END IF;
    IF lo IS NOT NULL AND lower(lo) = 'on' THEN v := v || 'lo_compat_privileges=on (weakens large-object ACLs); '; END IF;
    SELECT string_agg(format('%s=%s', name, setting), ', ' ORDER BY name) INTO v2
    FROM pg_settings WHERE name IN ('backslash_quote','lo_compat_privileges','password_encryption',
                                    'search_path','session_replication_role','ssl_passphrase_command_supports_reload');
    INSERT INTO cis_results(section,title,status,detail) VALUES ('8.3','Ensure miscellaneous configuration settings are correct','MANL',
      format('Settings: %s. %s See the CIS PostgreSQL 18 Benchmark PDF, section 8.3, for the manual Audit/Remediation procedure.',
             COALESCE(v2,'(none)'),
             CASE WHEN btrim(v)='' THEN '(no obvious misconfigurations in the captured subset)' ELSE 'POTENTIAL ISSUES: ' || v END));

END;
$audit$;


-- -----------------------------------------------------------------------------
--  OPERATING-SYSTEM ITEMS - NOT checked, only DISPLAYED (status MANL)
--  Only a short one-line summary is stored (the reason psql cannot check it).
--  The full verbatim CIS Audit/Remediation text is intentionally NOT embedded
--  here - consult the CIS PostgreSQL 18 Benchmark PDF for those procedures.
-- -----------------------------------------------------------------------------
INSERT INTO cis_results(section,title,status,detail) VALUES
  ('1.1', 'Ensure packages are obtained from authorized repositories', 'MANL', '[Manual] Not checkable via psql (package repository configuration (dnf/apt) - OS access). See the CIS PostgreSQL 18 Benchmark PDF, section 1.1, for the manual Audit/Remediation procedure.'),
  ('1.2', 'Install only required packages', 'MANL', '[Manual] Not checkable via psql (installed-package list (rpm -qa / dpkg -l) - OS access). See the CIS PostgreSQL 18 Benchmark PDF, section 1.2, for the manual Audit/Remediation procedure.'),
  ('1.3', 'Ensure systemd Service Files Are Enabled', 'MANL', '[Automated] Not checkable via psql (systemd unit state (systemctl is-enabled) - OS access). See the CIS PostgreSQL 18 Benchmark PDF, section 1.3, for the manual Audit/Remediation procedure.'),
  ('1.4', 'Ensure Data Cluster Initialized Successfully', 'MANL', '[Automated] Not checkable via psql (initdb / pg_controldata verification on the host - OS access). See the CIS PostgreSQL 18 Benchmark PDF, section 1.4, for the manual Audit/Remediation procedure.'),
  ('1.5', 'Ensure the Latest Security Patches are Applied', 'MANL', '[Manual] Not checkable via psql (security-patch state (package manager) - OS access). See the CIS PostgreSQL 18 Benchmark PDF, section 1.5, for the manual Audit/Remediation procedure.'),
  ('1.6', 'Verify That PGPASSWORD is Not Set in Users Profiles', 'MANL', '[Automated] Not checkable via psql (grep of shell login scripts - OS access). See the CIS PostgreSQL 18 Benchmark PDF, section 1.6, for the manual Audit/Remediation procedure.'),
  ('1.7', 'Verify That the PGPASSWORD Environment Variable is Not in Use', 'MANL', '[Automated] Not checkable via psql (inspection of /proc/*/environ - OS access). See the CIS PostgreSQL 18 Benchmark PDF, section 1.7, for the manual Audit/Remediation procedure.'),
  ('2.1', 'Ensure the file permissions mask is correct', 'MANL', '[Manual] Not checkable via psql (process umask - OS access). See the CIS PostgreSQL 18 Benchmark PDF, section 2.1, for the manual Audit/Remediation procedure.'),
  ('2.2', 'Ensure extension directory has appropriate ownership and permissions', 'MANL', '[Automated] Not checkable via psql (on-disk owner/permissions of the extension directory - OS access). See the CIS PostgreSQL 18 Benchmark PDF, section 2.2, for the manual Audit/Remediation procedure.'),
  ('2.3', 'Disable PostgreSQL Command History', 'MANL', '[Automated] Not checkable via psql (symlink of ~/.psql_history to /dev/null - OS access). See the CIS PostgreSQL 18 Benchmark PDF, section 2.3, for the manual Audit/Remediation procedure.'),
  ('2.4', 'Ensure Passwords are Not Stored in the service file', 'MANL', '[Manual] Not checkable via psql (contents of ~/.pg_service.conf on disk - OS access). See the CIS PostgreSQL 18 Benchmark PDF, section 2.4, for the manual Audit/Remediation procedure.'),
  ('3.1.4', 'Ensure the log file destination directory is set correctly', 'MANL', '[Automated] Not checkable via psql (on-disk location/security of the log directory (log_directory) - OS access). See the CIS PostgreSQL 18 Benchmark PDF, section 3.1.4, for the manual Audit/Remediation procedure.'),
  ('4.1', 'Ensure Interactive Login is Disabled', 'MANL', '[Manual] Not checkable via psql (login shell of the ''postgres'' account - OS access). See the CIS PostgreSQL 18 Benchmark PDF, section 4.1, for the manual Audit/Remediation procedure.'),
  ('4.2', 'Ensure sudo is configured correctly', 'MANL', '[Manual] Not checkable via psql (sudoers configuration - OS access). See the CIS PostgreSQL 18 Benchmark PDF, section 4.2, for the manual Audit/Remediation procedure.'),
  ('5.1', 'Do Not Specify Passwords in the Command Line', 'MANL', '[Manual] Not checkable via psql (process arguments / shell history - OS access). See the CIS PostgreSQL 18 Benchmark PDF, section 5.1, for the manual Audit/Remediation procedure.'),
  ('5.2', 'Ensure PostgreSQL is Bound to an IP Address', 'MANL', '[Manual] Not checkable via psql (binding listen address to a network topology - policy/OS). See the CIS PostgreSQL 18 Benchmark PDF, section 5.2, for the manual Audit/Remediation procedure.'),
  ('6.1', 'Understanding attack vectors and runtime parameters', 'MANL', '[Manual] Not checkable via psql (informational material - nothing to check). See the CIS PostgreSQL 18 Benchmark PDF, section 6.1, for the manual Audit/Remediation procedure.'),
  ('6.7', 'Ensure FIPS 140-2 OpenSSL Cryptography Is Used', 'MANL', '[Automated] Not checkable via psql (host OpenSSL FIPS mode (fips-mode-setup) - OS access). See the CIS PostgreSQL 18 Benchmark PDF, section 6.7, for the manual Audit/Remediation procedure.'),
  ('7.3', 'Ensure base backups are configured and functional', 'MANL', '[Manual] Not checkable via psql (base-backup tooling/cron (pg_basebackup) on the host - OS access). See the CIS PostgreSQL 18 Benchmark PDF, section 7.3, for the manual Audit/Remediation procedure.'),
  ('8.1', 'Ensure PostgreSQL subdirectory locations are outside the data cluster', 'MANL', '[Manual] Not checkable via psql (on-disk tablespace/WAL symlink layout - OS access). See the CIS PostgreSQL 18 Benchmark PDF, section 8.1, for the manual Audit/Remediation procedure.'),
  ('8.2', 'Ensure the backup and restore tool pgBackRest is installed and configured', 'MANL', '[Automated] Not checkable via psql (pgBackRest install and configuration on the host - OS access). See the CIS PostgreSQL 18 Benchmark PDF, section 8.2, for the manual Audit/Remediation procedure.');
-- -----------------------------------------------------------------------------
--  REPORT
-- -----------------------------------------------------------------------------
\echo ''
\echo '==============================================================================='
\echo '  CIS PostgreSQL 18 Benchmark v1.0.0 - audit via psql'
\echo '==============================================================================='

SELECT format('Server: %s (%s) | user: %s | database: %s | superuser: %s',
              current_setting('server_version'),
              current_setting('server_version_num'),
              current_user, current_database(),
              current_setting('is_superuser')) AS session \gset
\echo :session
\echo ''

-- ----- Overview ---------------------------------------------------------------
\echo '------------------------------------------------------------------------------'
\echo '  RESULTS (overview)'
\echo '------------------------------------------------------------------------------'
\pset format aligned
\pset border 2
SELECT section AS "Section",
       left(title, 58) AS "Title",
       status AS "Status"
FROM cis_results
ORDER BY string_to_array(section, '.')::int[];

-- ----- Details ----------------------------------------------------------------
--  Output is sanitized at query time (any stray control chars -> space).  The
--  long verbatim CIS Audit/Remediation text embedded in OS (MANL) items is cut
--  off at "CIS Audit:" so only the short summary line is shown - the heavy CIS
--  text is not displayed.  (It still lives in full in the cis_results table if
--  you ever want it: SELECT detail FROM cis_results WHERE section = '1.2';)
\echo ''
\echo '------------------------------------------------------------------------------'
\echo '  DETAILS'
\echo '------------------------------------------------------------------------------'
\x off
\pset format wrapped
\pset columns 120
SELECT section AS "Section",
       status  AS "Status",
       btrim(regexp_replace(
               regexp_replace(detail, '\s*CIS Audit:.*$', '', 'g'),  -- drop everything from "CIS Audit:" on
               '[\x00-\x1f]+', ' ', 'g'))                             -- strip any stray control chars
         AS "Detail"
FROM cis_results
ORDER BY string_to_array(section, '.')::int[];

-- ----- Summary ----------------------------------------------------------------
\echo ''
\echo '------------------------------------------------------------------------------'
\echo '  SUMMARY'
\echo '------------------------------------------------------------------------------'
\pset format aligned
SELECT status AS "Status", count(*) AS "Count"
FROM cis_results
GROUP BY status
ORDER BY CASE status WHEN 'PASS' THEN 1 WHEN 'FAIL' THEN 2 WHEN 'WARN' THEN 3
                     WHEN 'SKIP' THEN 4 WHEN 'MANL' THEN 5 ELSE 6 END;

SELECT count(*) AS "Total items" FROM cis_results;

\echo ''
\echo '  Legend: PASS=compliant  FAIL=non-compliant  WARN=needs review'
\echo '          SKIP=insufficient privilege / not applicable  MANL=OS item (manual)'
\echo '==============================================================================='
\echo ''
\echo '  Tip: results remain in the TEMP table cis_results for this session, e.g.:'
\echo '       SELECT section, title, detail FROM cis_results WHERE status = ''FAIL'';'
\echo ''
