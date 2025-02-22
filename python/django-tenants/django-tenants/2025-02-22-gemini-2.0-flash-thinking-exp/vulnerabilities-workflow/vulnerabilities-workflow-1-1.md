### Vulnerability List

- Vulnerability Name: Insecure Default Privileges Cloning in Schema Cloning
- Description:
    1. An attacker with tenant creation privileges can trigger schema cloning functionality.
    2. The `clone_schema` function in `django-tenants/clone.py` attempts to clone database schema, including default privileges.
    3. Within the `PRIVS: Defaults` section of `CLONE_SCHEMA_FUNCTION`, the code parses Access Control List (ACL) strings of default privileges from the source schema.
    4. Based on parsed ACLs, it constructs and executes `ALTER DEFAULT PRIVILEGES` statements in the destination (cloned) schema.
    5. Due to potentially flawed logic in parsing and re-constructing these `ALTER DEFAULT PRIVILEGES` statements, broader default privileges than intended might be granted in the cloned schema.
    6. This can lead to newly created database objects (tables, sequences, functions) within the cloned tenant having overly permissive default Access Control Lists (ACLs).
    7. Consequently, users and roles might gain unintended default access to these newly created objects, leading to privilege escalation within the cloned tenant.
- Impact: Privilege escalation within newly created tenants. Objects created in cloned tenants might have overly permissive default ACLs, allowing unauthorized data access or modification.
- Vulnerability Rank: High
- Currently Implemented Mitigations:
    - None. The code does not have specific mitigations against insecure default privilege cloning. Schema name validation is present, but it does not address the logic within the `CLONE_SCHEMA_FUNCTION` related to ACL parsing and privilege re-application.
- Missing Mitigations:
    - Robust ACL Parsing and Validation: Implement more secure and reliable parsing of PostgreSQL ACL strings to accurately determine the intended privileges.
    - Least Privilege Principle for Cloning: Ensure that the cloned default privileges are no broader than the original default privileges in the source schema. Ideally, default privileges should be cloned with caution, and only when absolutely necessary. Consider options to avoid cloning default privileges altogether or provide granular control over which default privileges are cloned.
    - Targeted Unit Tests: Develop comprehensive unit tests specifically focused on verifying the correctness and security of permission cloning, particularly for default privileges. These tests should confirm that cloned schemas have the expected and secure default privileges, preventing unintended privilege escalation.
- Preconditions:
    - The application must use the schema cloning feature of `django-tenants` for tenant creation.
    - A privileged user (e.g., administrator) must be able to initiate tenant creation, which in turn triggers schema cloning.
    - The source schema used for cloning must have custom default privileges set (i.e., default privileges different from the PostgreSQL defaults).
- Source Code Analysis:
    - File: `/code/django_tenants/clone.py`
    - Function: `CLONE_SCHEMA_FUNCTION`
    - Vulnerable Section: `PRIVS: Defaults`

    ```sql
    -- ---------------------
    -- MV: Permissions: Defaults
    -- ---------------------
    action := 'PRIVS: Defaults';
    cnt := 0;
    FOR arec IN
      SELECT pg_catalog.pg_get_userbyid(d.defaclrole) AS "owner", n.nspname AS schema,
      CASE d.defaclobjtype WHEN 'r' THEN 'table' WHEN 'S' THEN 'sequence' WHEN 'f' THEN 'function' WHEN 'T' THEN 'type' WHEN 'n' THEN 'schema' END AS atype,
      d.defaclacl as defaclacl, pg_catalog.array_to_string(d.defaclacl, ',') as defaclstr
      FROM pg_catalog.pg_default_acl d LEFT JOIN pg_catalog.pg_namespace n ON (n.oid = d.defaclnamespace) WHERE n.nspname IS NOT NULL and n.nspname = quote_ident(source_schema) ORDER BY 3, 2, 1
    LOOP
      BEGIN
        -- RAISE NOTICE 'owner=%  type=%  defaclacl=%  defaclstr=%', arec.owner, arec.atype, arec.defaclacl, arec.defaclstr;

        FOREACH aclstr IN ARRAY arec.defaclacl
        LOOP
            cnt := cnt + 1;
            -- RAISE NOTICE 'aclstr=%', aclstr;
            -- break up into grantor, grantee, and privs, mydb_update=rwU/mydb_owner
            SELECT split_part(aclstr, '=',1) INTO grantee;
            SELECT split_part(aclstr, '=',2) INTO grantor;
            SELECT split_part(grantor, '/',1) INTO privs;
            SELECT split_part(grantor, '/',2) INTO grantor;
            -- RAISE NOTICE 'grantor=%  grantee=%  privs=%', grantor, grantee, privs;

            IF arec.atype = 'function' THEN
              -- Just having execute is enough to grant all apparently.
              buffer := 'ALTER DEFAULT PRIVILEGES FOR ROLE ' || grantor || ' IN SCHEMA ' || quote_ident(dest_schema) || ' GRANT ALL ON FUNCTIONS TO "' || grantee || '";';
              IF ddl_only THEN
                RAISE INFO '%', buffer;
              ELSE
                EXECUTE buffer;
              END IF;

            ELSIF arec.atype = 'sequence' THEN
              IF POSITION('r' IN privs) > 0 AND POSITION('w' IN privs) > 0 AND POSITION('U' IN privs) > 0 THEN
                -- arU is enough for all privs
                buffer := 'ALTER DEFAULT PRIVILEGES FOR ROLE ' || grantor || ' IN SCHEMA ' || quote_ident(dest_schema) || ' GRANT ALL ON SEQUENCES TO "' || grantee || '";';
                IF ddl_only THEN
                  RAISE INFO '%', buffer;
                ELSE
                  EXECUTE buffer;
                END IF;

              ELSE
                -- have to specify each priv individually
                buffer2 := '';
                IF POSITION('r' IN privs) > 0 THEN
                      buffer2 := 'SELECT';
                END IF;
                IF POSITION('w' IN privs) > 0 THEN
                  IF buffer2 = '' THEN
                    buffer2 := 'UPDATE';
                  ELSE
                    buffer2 := buffer2 || ', UPDATE';
                  END IF;
                END IF;
                IF POSITION('U' IN privs) > 0 THEN
                      IF buffer2 = '' THEN
                    buffer2 := 'USAGE';
                  ELSE
                    buffer2 := buffer2 || ', USAGE';
                  END IF;
                END IF;
                buffer := 'ALTER DEFAULT PRIVILEGES FOR ROLE ' || grantor || ' IN SCHEMA ' || quote_ident(dest_schema) || ' GRANT ' || buffer2 || ' ON SEQUENCES TO "' || grantee || '";';
                IF ddl_only THEN
                  RAISE INFO '%', buffer;
                ELSE
                  EXECUTE buffer;
                END IF;

              END IF;
            ELSIF arec.atype = 'table' THEN
              -- do each priv individually, jeeeesh!
              buffer2 := '';
              IF POSITION('a' IN privs) > 0 THEN
                buffer2 := 'INSERT';
              END IF;
              IF POSITION('r' IN privs) > 0 THEN
                IF buffer2 = '' THEN
                  buffer2 := 'SELECT';
                ELSE
                  buffer2 := buffer2 || ', SELECT';
                END IF;
              END IF;
              IF POSITION('w' IN privs) > 0 THEN
                IF buffer2 = '' THEN
                  buffer2 := 'UPDATE';
                ELSE
                  buffer2 := buffer2 || ', UPDATE';
                END IF;
              END IF;
              IF POSITION('d' IN privs) > 0 THEN
                IF buffer2 = '' THEN
                  buffer2 := 'DELETE';
                ELSE
                  buffer2 := buffer2 || ', DELETE';
                END IF;
              END IF;
              IF POSITION('t' IN privs) > 0 THEN
                IF buffer2 = '' THEN
                  buffer2 := 'TRIGGER';
                ELSE
                  buffer2 := buffer2 || ', TRIGGER';
                END IF;
              END IF;
              IF POSITION('T' IN privs) > 0 THEN
                IF buffer2 = '' THEN
                  buffer2 := 'TRUNCATE';
                ELSE
                  buffer2 := buffer2 || ', TRUNCATE';
                END IF;
              END IF;
              buffer := 'ALTER DEFAULT PRIVILEGES FOR ROLE ' || grantor || ' IN SCHEMA ' || quote_ident(dest_schema) || ' GRANT ' || buffer2 || ' ON TABLES TO "' || grantee || '";';
              IF ddl_only THEN
                RAISE INFO '%', buffer;
              ELSE
                EXECUTE buffer;
              END IF;

            ELSE
                RAISE WARNING 'Doing nothing for type=%  privs=%', arec.atype, privs;
            END IF;
        END LOOP;
      END;
    END LOOP;
    ```

- Security Test Case:
    1. Prerequisites:
        - Running instance of an application built using `django-tenants`.
        - Administrative access to the application to create tenants.
        - PostgreSQL client (e.g., `psql`) to connect to the database directly.
    2. Steps:
        - Connect to the PostgreSQL database as a superuser (e.g., `postgres`).
        - Create a new schema to act as the source schema for cloning (e.g., `source_schema_vuln_test`).
        ```sql
        CREATE SCHEMA source_schema_vuln_test;
        ```
        - Set custom default privileges in the `source_schema_vuln_test` schema to grant `SELECT` privilege on tables to the `public` role.
        ```sql
        ALTER DEFAULT PRIVILEGES IN SCHEMA source_schema_vuln_test GRANT SELECT ON TABLES TO public;
        ```
        - Verify the default privileges are set:
        ```sql
        SELECT defaclobjtype, defaclacl FROM pg_default_acl WHERE defaclnamespace = 'source_schema_vuln_test'::regnamespace;
        ```
        You should see an entry like `defaclobjtype | defaclacl` with values like `r` and `"{=r/postgres,public=r/postgres}"`.
        - Using the application's admin interface or tenant creation functionality, create a new tenant named `vuln_test_tenant` and configure it to clone from the `source_schema_vuln_test` schema (if the application allows specifying a base schema for cloning; if not, you may need to modify test setup to use a schema with default privileges already set).
        - Create a user `attacker_user` within the public schema of the application (or use an existing low-privileged user).
        - Connect to the PostgreSQL database as a superuser again.
        - Switch the database connection to the schema of the newly created tenant `vuln_test_tenant`.
        ```sql
        SET search_path TO vuln_test_tenant;
        ```
        - Create a new table `sensitive_data` in the `vuln_test_tenant` schema as a privileged user.
        ```sql
        CREATE TABLE sensitive_data (data TEXT);
        INSERT INTO sensitive_data VALUES ('Confidential Information');
        ```
        - Now, as `attacker_user`, attempt to access the `sensitive_data` table in the `vuln_test_tenant` schema through the application. For example, if there's a Django shell accessible within the tenant context:
        ```python
        from django.db import connection
        connection.set_schema('vuln_test_tenant') # Or however you switch tenant context programmatically
        from django.db import connection, connections
        cursor = connections['default'].cursor()
        cursor.execute("SELECT * FROM sensitive_data;")
        rows = cursor.fetchall()
        print(rows)
        ```
    3. Expected Result:
        - **Vulnerable:** The `attacker_user` is able to successfully query and retrieve data from the `sensitive_data` table. This indicates that the default `SELECT` privilege from `source_schema_vuln_test` was incorrectly cloned to `vuln_test_tenant`, granting unintended `SELECT` access to the `public` role by default for newly created tables.
        - **Mitigated:** The `attacker_user` is denied access when trying to query the `sensitive_data` table, resulting in a permission error. This would indicate that default privileges were not incorrectly cloned, and access is correctly restricted unless explicitly granted for specific tables.