Here is the combined list of vulnerabilities, formatted as markdown:

### Vulnerability List:

* Vulnerability Name: Insecure Default Privileges Cloning in Schema Cloning

* Description:
    1. An attacker with tenant creation privileges can trigger schema cloning functionality.
    2. The `clone_schema` function in `django-tenants/clone.py` attempts to clone database schema, including default privileges.
    3. Within the `PRIVS: Defaults` section of `CLONE_SCHEMA_FUNCTION`, the code parses Access Control List (ACL) strings of default privileges from the source schema.
    4. Based on parsed ACLs, it constructs and executes `ALTER DEFAULT PRIVILEGES` statements in the destination (cloned) schema.
    5. Due to potentially flawed logic in parsing and re-constructing these `ALTER DEFAULT PRIVILEGES` statements, broader default privileges than intended might be granted in the cloned schema.
    6. This can lead to newly created database objects (tables, sequences, functions) within the cloned tenant having overly permissive default Access Control Lists (ACLs).
    7. Consequently, users and roles might gain unintended default access to these newly created objects, leading to privilege escalation within the cloned tenant.

* Impact: Privilege escalation within newly created tenants. Objects created in cloned tenants might have overly permissive default ACLs, allowing unauthorized data access or modification.

* Vulnerability Rank: High

* Currently Implemented Mitigations:
    - None. The code does not have specific mitigations against insecure default privilege cloning. Schema name validation is present, but it does not address the logic within the `CLONE_SCHEMA_FUNCTION` related to ACL parsing and privilege re-application.

* Missing Mitigations:
    - Robust ACL Parsing and Validation: Implement more secure and reliable parsing of PostgreSQL ACL strings to accurately determine the intended privileges.
    - Least Privilege Principle for Cloning: Ensure that the cloned default privileges are no broader than the original default privileges in the source schema. Ideally, default privileges should be cloned with caution, and only when absolutely necessary. Consider options to avoid cloning default privileges altogether or provide granular control over which default privileges are cloned.
    - Targeted Unit Tests: Develop comprehensive unit tests specifically focused on verifying the correctness and security of permission cloning, particularly for default privileges. These tests should confirm that cloned schemas have the expected and secure default privileges, preventing unintended privilege escalation.

* Preconditions:
    - The application must use the schema cloning feature of `django-tenants` for tenant creation.
    - A privileged user (e.g., administrator) must be able to initiate tenant creation, which in turn triggers schema cloning.
    - The source schema used for cloning must have custom default privileges set (i.e., default privileges different from the PostgreSQL defaults).

* Source Code Analysis:
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

* Security Test Case:
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

* Vulnerability Name: Hard‑coded Django Secret Key
  * Description:
  The Django settings files (for example, in the tenants’ settings under both the multi‐tenant and test project directories) contain secret keys hard-coded as plain strings (e.g.,
  `SECRET_KEY = 'as-%*_93v=r5*p_7cu8-%o6b&x^g+q$#*e*fl)k)x0-t=%q0qa'` and a different value in the dts‑test project). An external attacker (or anyone who obtains access to the source code) can use these exposed keys to forge cryptographic signatures, hijack sessions, or tamper with signed data.
  * Impact:
  - Possibility to forge session cookies and other signed tokens.
  - Risk of privilege escalation, account impersonation, and unauthorized access to sensitive functionality.
  * Vulnerability Rank: Critical
  * Currently Implemented Mitigations:
  - None. The secret key is embedded directly in several settings files.
  * Missing Mitigations:
  - The secret key should be injected from environment variables or an external secrets manager rather than hard‑coded.
  * Preconditions:
  - The deployed instance uses the provided settings files without overriding the hard-coded SECRET_KEY.
  * Source Code Analysis:
  - Several settings files (e.g. in `tenant_multi_types_tutorial/settings.py` and `dts_test_project/dts_test_project/settings.py`) set `SECRET_KEY` to a literal string. No dynamic loading or secret management is applied.
  * Security Test Case:
  1. Confirm that the deployed instance is using one of these settings files (for example by checking a misconfigured debug endpoint or source disclosure vulnerability).
  2. Using the known secret key, attempt to forge a session cookie or valid signed token (e.g. for password resets) and submit it with a request.
  3. Verify that the application accepts the forged signature—indicating that the key is being used for critical cryptographic operations.

* Vulnerability Name: DEBUG Mode Enabled in Production Settings
  * Description:
  Multiple settings files (for example in `tenant_tutorial/settings.py` and in `dts_test_project/dts_test_project/settings.py`) set `DEBUG = True`. In a production environment this configuration can cause detailed error pages (stack traces, variable dumps, and internal configuration details) to be displayed when an exception occurs. An attacker could intentionally trigger an error to obtain sensitive internal data.
  * Impact:
  - Detailed error information disclosure that aids in further exploitation (revealing file paths, settings, database names, etc.).
  - Increases the risk for other attacks by providing internal configuration details.
  * Vulnerability Rank: High
  * Currently Implemented Mitigations:
  - None; the settings files show a hard‑coded `DEBUG = True`.
  * Missing Mitigations:
  - In production, `DEBUG` must be set to `False` (preferably via an environment variable) and error reporting should be appropriately configured.
  * Preconditions:
  - The instance is deployed with a settings file that has `DEBUG=True` (typically a mis‑configuration for production).
  * Source Code Analysis:
  - In each relevant settings file, the value of `DEBUG` is set as a literal true value with no conditional override for production.
  * Security Test Case:
  1. Force an error (for example, by visiting a deliberately broken URL or triggering an exception in a view).
  2. Verify that the response displays a full debug traceback with sensitive information.
  3. Confirm that this information would enable an attacker to gain insight into the application’s internals.

* Vulnerability Name: Unauthenticated User Account Reset via Random Form View
  * Description:
  The view named `TenantViewRandomForm` (found in both `tenant_type_one_only/views.py` and similarly in `tenant_tutorial/customers/views.py`) uses a form‐processing method that immediately deletes all user accounts using the call `User.objects.all().delete()` before generating random user accounts. Importantly, there is no authentication or authorization check on this view. An attacker (or a victim forced via a CSRF attack) could trigger this endpoint to wipe out all legitimate users and replace them with attacker–controlled random ones.
  * Impact:
  - Loss of all legitimate user accounts.
  - Potential full account takeover and denial of service for genuine users.
  * Vulnerability Rank: Critical
  * Currently Implemented Mitigations:
  - None. The view is publicly accessible and does not require any authentication.
  * Missing Mitigations:
  - Enforce strong authentication (e.g. add a login_required decorator or restrict access via permissions) on sensitive account management views.
  * Preconditions:
  - The endpoint (e.g. `/sample-random/`) is exposed and an attacker can submit an HTTP POST (possibly via CSRF exploitation if the victim’s credentials are co-opted).
  * Source Code Analysis:
  - In the `form_valid()` method of `TenantViewRandomForm`, the code calls `User.objects.all().delete()` without any check of the user’s privileges or identity.
  * Security Test Case:
  1. Simulate a valid POST request to the `/sample-random/` URL (this may require acquiring a valid CSRF token by accessing the GET endpoint first).
  2. Verify that upon successful submission, all existing user records are deleted and new randomly generated user accounts are inserted.
  3. Confirm that this results in loss of legitimate credentials.

* Vulnerability Name: Unauthenticated Arbitrary File Upload
  * Description:
  The view `TenantViewFileUploadCreate` (located in `tenant_type_one_only/views.py` and similarly in `tenant_tutorial/customers/views.py`) is a simple Django CreateView based on the `UploadFile` model. This model uses a `FileField` with an `upload_to` attribute set to store files in the “uploads/” directory, and the view does not enforce any authentication or file‑type/size restrictions. An attacker could use this endpoint to upload a malicious file (for example, a script file) that—if later served directly—could be executed by the web server.
  * Impact:
  - Allows an attacker to store arbitrary files on the server.
  - In the worst‑case scenario—if the upload directory is served as executable content—this can lead to remote code execution, defacement, or further compromise of the system.
  * Vulnerability Rank: High
  * Currently Implemented Mitigations:
  - No custom file type validation or authentication checks are found in the view.
  * Missing Mitigations:
  - Require user authentication and proper authorization to access file–upload endpoints.
  - Validate the file type, size, and content before storing the file.
  - Store uploaded files outside of web‑accessible directories (or serve them in a non‑executable manner).
  * Preconditions:
  - The `/upload-file/` endpoint is publicly accessible and the directory “uploads/” is served by the web server.
  * Source Code Analysis:
  - The `UploadFile` model (in `tenant_type_one_only/models.py`) defines a `FileField` with no extra validators.
  - The CreateView `TenantViewFileUploadCreate` is opened on a public URL (as seen in the URL config), with no authentication added.
  * Security Test Case:
  1. Send a multipart POST request to `/upload-file/` with a file having a dangerous extension (e.g., a `.php` or `.py` file) containing malicious code.
  2. After successful upload (verify by checking the database/model), attempt to access the file via its served URL.
  3. Confirm whether the file is served for download or (worse) is executed by the web server.

* Vulnerability Name: Default pgAdmin Credentials
  * Description:
  The Docker Compose configuration (in `docker-compose.yml`) for the pgAdmin service provides default credentials via environment variables. If not overridden by production environment variables, the default email is set to `pgadmin4@pgadmin.org` and the default password to `admin`. An attacker can easily guess these credentials and log in to the pgAdmin interface to gain administrative access to the database.
  * Impact:
  - Unauthorized access to the database management interface.
  - Potential data theft, modification, or deletion.
  * Vulnerability Rank: High
  * Currently Implemented Mitigations:
  - The use of environment variable fallbacks (e.g., `${PGADMIN_DEFAULT_EMAIL:-pgadmin4@pgadmin.org}`) is present, but the defaults themselves remain weak.
  * Missing Mitigations:
  - Change the default credentials to strong values via environment variables in production deployments.
  * Preconditions:
  - The pgAdmin service is deployed on a publicly reachable host/port (e.g., port 5050) without custom credentials.
  * Source Code Analysis:
  - In the `docker-compose.yml` file, pgAdmin is configured with default credentials if no environment variables are specified.
  * Security Test Case:
  1. Connect to the pgAdmin web interface using a browser targeting the mapped public port (default 5050).
  2. Attempt to log in using the default credentials (email: `pgadmin4@pgadmin.org`, password: `admin`).
  3. Verify that access is granted and the database administration interface is available.

* Vulnerability Name: Default PostgreSQL Credentials
  * Description:
  In the Docker Compose file, the PostgreSQL service is started with default credentials:
  - `POSTGRES_USER=django_tenants`
  - `POSTGRES_PASSWORD=django_tenants`
  Additionally, the service maps port 5433 on the host to the container’s PostgreSQL port. These well‑known credentials put the database at risk if the port is exposed publicly.
  * Impact:
  - An attacker may connect to the PostgreSQL service and perform unauthorized queries or data modifications across tenants.
  * Vulnerability Rank: High
  * Currently Implemented Mitigations:
  - No mitigation is implemented; the credentials are directly hard‑coded in the docker‑compose configuration.
  * Missing Mitigations:
  - Use strong, unique credentials for the database by supplying them as secure environment variables.
  * Preconditions:
  - The PostgreSQL port (mapped to 5433) is open to external (or untrusted network) access, and the defaults remain in place.
  * Source Code Analysis:
  - The `docker-compose.yml` file under the `db` service clearly specifies these default credentials.
  * Security Test Case:
  1. From an external system, attempt a PostgreSQL connection to the host on port 5433 using the username “django_tenants” and password “django_tenants”.
  2. Run a simple SQL query (e.g., `SELECT current_database();`) to verify that access has been granted.
  3. Confirm that the database is vulnerable to unauthorized access.

* Vulnerability Name: Exposed Redis Service Without Authentication
  * Description:
  The Docker Compose configuration also maps the Redis service’s port 6379 on the host (via the mapping `"6379:6379"`). No authentication (or password) is configured for Redis. This leaves the Redis instance open to anyone who can reach the mapped port, allowing for arbitrary commands and data manipulation.
  * Impact:
  - An attacker can connect to Redis and perform commands that delete cached data, manipulate session data or, in some scenarios, deploy techniques to extract or inject data.
  * Vulnerability Rank: High
  * Currently Implemented Mitigations:
  - No authentication is configured for the Redis service in the Compose file.
  * Missing Mitigations:
  - Configure Redis with a strong password (using the “requirepass” option) and restrict network access (for example, via firewall rules or binding only to internal interfaces).
  * Preconditions:
  - The Redis service is accessible externally through port 6379.
  * Source Code Analysis:
  - The `docker-compose.yml` file declares a Redis service that simply uses the official image and opens port 6379 without any further authentication parameters.
  * Security Test Case:
  1. Use a Redis client from an external host and connect to the exposed port 6379.
  2. Issue a command such as `INFO` or even `FLUSHALL` to check if the attacker can read or clear the cache.
  3. Verify that the Redis instance accepts and executes commands without authentication.

* Vulnerability Name: Insecure ALLOWED_HOSTS Configuration
  * Description:
  Several settings files (for example, in `tenant_multi_types_tutorial/settings.py` and `tenant_tutorial/settings.py`) set
  `ALLOWED_HOSTS = ['*']`. This configuration accepts any host header supplied in an HTTP request. An attacker may exploit such a configuration in host‑header poisoning attacks that could mislead URL generation, bypass security controls, or facilitate phishing schemes.
  * Impact:
  - Host header poisoning may allow malicious redirection, bypassing of certain security checks, or help an attacker craft phishing pages that appear to belong to the legitimate domain.
  * Vulnerability Rank: High
  * Currently Implemented Mitigations:
  - None; the settings plainly allow all hosts by using a wildcard.
  * Missing Mitigations:
  - In production, restrict ALLOWED_HOSTS to the known, trusted domain names.
  * Preconditions:
  - The instance is deployed using these settings (i.e. ALLOWED_HOSTS is left as `['*']`) so that any HTTP Host header is accepted.
  * Source Code Analysis:
  - In the settings files (e.g., under `tenant_multi_types_tutorial/settings.py`), the ALLOWED_HOSTS configuration is clearly set as `['*']`.
  * Security Test Case:
  1. Send an HTTP request to the application with a custom, attacker‑controlled Host header.
  2. Analyze whether the application uses this header in URL generation or error messages.
  3. Verify that no validation is performed and that the response reflects the malicious host information.

* Vulnerability Name: Lack of Tenant Schema Name Validation Leading to Directory Traversal
  * Description:
  The multi–tenant architecture relies on a tenant’s schema name to dynamically build filesystem paths used in template loading, static file serving, and file storage (e.g. in the construction of storage base paths in `TenantStaticFilesStorage` and template loader directories using `settings.MULTITENANT_TEMPLATE_DIRS`). However, there is no explicit validation or sanitization of tenant schema names when they are created (for example, in the management command `create_tenant.py`) or when they are injected into path formatting operations. An attacker who can supply a malicious schema name (for example, using directory traversal sequences like "`../../`") may manipulate these paths to reference directories and files outside the intended tenant boundaries.
  * Impact:
  - An attacker may access or modify files outside the designated tenant folder, leading to data disclosure or file manipulation.
  - In the worst case, this could allow uploading, serving, or even execution of arbitrary files located on or written to parts of the filesystem that should remain isolated from tenant operations.
  * Vulnerability Rank: Critical
  * Currently Implemented Mitigations:
  - No input validation or sanitization is performed on tenant schema names in the provided project files.
  * Missing Mitigations:
  - Enforce a strict whitelist or regular expression (allowing only safe characters such as alphanumeric characters and underscores) when accepting tenant schema names.
  - Sanitize any input used in filesystem path constructions and avoid using raw string formatting to build directory paths.
  * Preconditions:
  - The application allows external creation or alteration of tenants (for example, via a self‑service signup or an admin interface) without enforcing strict rules on the tenant schema name.
  - Filesystem locations (e.g. for static files, media files, and templates) are computed by directly substituting the tenant schema name into a pre‑configured path pattern.
  * Source Code Analysis:
  - In `TenantStaticFilesStorageTestCase` (see file `/code/django_tenants/tests/staticfiles/test_storage.py`), the base location for tenant files is computed using `"{}/{}".format(self.temp_dir, connection.schema_name)` without sanitizing `connection.schema_name`.
  - In the template loader tests (in `/code/django_tenants/tests/template/loaders/test_filesystem.py`), the directory for templates is set via `settings.MULTITENANT_TEMPLATE_DIRS[0] % self.tenant.schema_name`—again relying on the raw value of the tenant schema name.
  - The management command `create_tenant.py` accepts tenant schema names directly from user input without validating that the input conforms to a safe pattern.
  * Security Test Case:
  1. Using an available tenant creation mechanism (for example, via the self‑service interface or by simulating the management command), create a new tenant with a malicious schema name such as "`../../evil`".
  2. Verify that the filesystem path computed for this tenant’s static or media files (or for template lookup) is outside the intended directory. For example, if the base path is constructed as `"{}/{}".format(<STATIC_ROOT>, schema_name)`, check that the resolved path escapes `<STATIC_ROOT>`.
  3. Attempt to upload a file (or access a static file) using this tenant’s endpoints.
  4. Confirm that the file is stored or served from an unintended location, demonstrating a directory traversal vulnerability.
  5. Review the application’s response and server logs to ensure that the exploitation did indeed lead to access (read or write) to files outside of the designated tenant directory.

* Vulnerability Name: Tenant Data Leakage via Insecure Schema Cloning

* Description:
    1. An attacker gains access to create a new tenant (if tenant creation is publicly accessible or after compromising an admin account).
    2. During tenant creation, the system clones an existing schema (e.g., 'empty' schema as seen in `run_tests.sh`) to initialize the new tenant's schema.
    3. If the 'empty' schema contains any sensitive data, or if the cloning process does not properly sanitize or isolate data, the new tenant schema will inherit this data.
    4. Subsequently, users of the newly created tenant can access and potentially exploit this leaked data, which may belong to the template tenant or even the public schema if the template schema was not properly isolated.

* Impact:
    - High: Sensitive data from a template schema (intended to be empty or contain only baseline configurations) or even the public schema can be leaked into newly created tenant schemas. This can lead to unauthorized access to confidential information, privacy violations, and potential compliance issues.
    - Depending on the nature of the leaked data, it could include personally identifiable information (PII), application secrets, or other critical business data.

* Vulnerability Rank: High

* Currently Implemented Mitigations:
    - The project provides a `clone_schema` function in `django_tenants/clone.py` which is used to copy schema structure and optionally data.
    - The `run_tests.sh` script uses `clone_tenant` management command with `--clone_from empty --clone_tenant_fields False` options, suggesting an awareness of potential data leakage when cloning tenant specific fields, but not data leakage from the template schema itself.
    - The `clone_tenant` management command provides `--clone_tenant_fields False` option to avoid cloning tenant-specific fields.

* Missing Mitigations:
    - **Secure Template Schema Isolation:** The project lacks a clear mechanism to ensure that template schemas used for cloning (like 'empty') are genuinely empty of sensitive data and properly isolated. Developers using django-tenants are responsible for creating and maintaining secure template schemas, but the framework itself doesn't enforce this.
    - **Data Sanitization during Cloning:** The `clone_schema` function, by design, can copy data from the template schema. Even when the intention is to clone only the schema structure, there's no explicit step within the framework to sanitize or verify the absence of sensitive data in the template schema before cloning the schema structure. The risk persists that if the template schema is not properly maintained as truly empty, sensitive data will be cloned.
    - **Tenant Creation Access Control:** While not directly related to cloning, if tenant creation is not properly access-controlled (e.g., publicly available without authentication), attackers can more easily exploit this vulnerability by creating numerous tenants and examining the cloned data. The management commands like `create_tenant` and `clone_tenant` should ideally only be accessible to administrators.

* Preconditions:
    - Tenant creation functionality must be available, either publicly or through compromised admin access.
    - The system must be configured to use schema cloning for tenant initialization.
    - A template schema (like 'empty') is used as the source for cloning.
    - The template schema, despite being intended as a template, inadvertently contains sensitive data.

* Source Code Analysis:
    1. **`django_tenants/clone.py` - `clone_schema` function:**
        ```python
        class CloneSchema:
            # ...
            def clone_schema(self, base_schema_name, new_schema_name, set_connection=True):
                # ...
                cursor = connection.cursor()
                # ...
                sql = 'SELECT clone_schema(%(base_schema)s, %(new_schema)s, true, false)' # include_recs=true is used here in example
                cursor.execute(
                    sql,
                    {'base_schema': base_schema_name, 'new_schema': new_schema_name}
                )
                cursor.close()
        ```
        - The `clone_schema` function in `CloneSchema` class utilizes a raw SQL function `clone_schema` (defined within `django_tenants/db/sql/functions/clone_schema.sql`).
        - Critically, the example code in `clone_schema` function itself uses `include_recs=true` as a parameter in the SQL call. This means, by default and as demonstrated in the code, the cloning process includes copying records (data).
        - While the `clone_tenant` management command in `run_tests.sh` uses `--clone_tenant_fields False`, this option is specific to tenant fields and does not prevent the cloning of data from other tables within the template schema because `CloneSchema().clone_schema()` defaults to `include_recs=True`.
        - The SQL function `clone_schema` (within `CLONE_SCHEMA_FUNCTION` in `django_tenants/db/sql/functions.py` and defined in `django_tenants/db/sql/functions/clone_schema.sql`) is designed to copy schema structure, sequences, tables, views, functions, and optionally data based on the `include_recs boolean` parameter.

    2. **`run_tests.sh`:**
        ```bash
        greenprint "Execute clone_tenant"
        PYTHONWARNINGS=d python manage.py clone_tenant \
            --clone_from empty --clone_tenant_fields False \
            --schema_name a-cloned-tenant --name "A cloned tenant" --description "This tenant was created by cloning" \
            --type type1 --domain-domain a-cloned-tenant.example.com --domain-is_primary True
        ```
        - This script demonstrates the usage of `clone_tenant` management command, explicitly setting `--clone_tenant_fields False` to avoid cloning tenant fields. However, it uses 'empty' as the `--clone_from` schema, implying that the developers expect this schema to be genuinely empty. If 'empty' schema is not properly maintained and contains data, this script, and any tenant creation process using cloning, would be vulnerable.

    3. **`django_tenants/management/commands/clone_tenant.py`:**
        ```python
        class Command(TenantCommand):
            help = "Clones a tenant's schema"

            def add_arguments(self, parser):
                super().add_arguments(parser)
                parser.add_argument('--clone_from', required=True, help='Schema name to clone from')
                parser.add_argument('--clone_tenant_fields', action='store_true', dest='clone_tenant_fields',
                                    default=False, help='Clone tenant fields')
                # ...

            def handle_tenant(self, tenant, **options):
                clone_from = options['clone_from']
                clone_tenant_fields = options['clone_tenant_fields']
                verbosity = int(options['verbosity'])

                if schema_exists(tenant.schema_name):
                    raise CommandError("Schema '%s' already exists" % tenant.schema_name)

                clone_schema = CloneSchema()
                clone_schema.clone_schema(clone_from, tenant.schema_name) # include_recs=True is hardcoded in CloneSchema.clone_schema

                if clone_tenant_fields:
                    # Clone tenant fields is not fully implemented and may lead to issues.
                    # It's better to create a new tenant and then clone the schema.
                    # This is left for future implementation.
                    warnings.warn("Cloning tenant fields is not fully implemented and may lead to issues.")
                    # ...
        ```
        - The `clone_tenant` command utilizes `CloneSchema().clone_schema()`. It's crucial to note that `CloneSchema().clone_schema()` in `django_tenants/clone.py` defaults to calling the underlying SQL `clone_schema` function with `include_recs=True`.
        - The `--clone_tenant_fields False` option in the management command only affects the cloning of tenant-specific fields. It does **not** prevent the cloning of data from the template schema itself because `include_recs=True` is hardcoded in `CloneSchema().clone_schema()` and not configurable via the management command. This means that even when using `--clone_tenant_fields False`, all data within the template schema will still be cloned into the new tenant's schema.

* Security Test Case:
    1. **Setup:**
        - Create a template tenant (e.g., schema name: 'empty') and intentionally insert some sensitive test data into a table within this schema (e.g., a table named 'leaked_data' with a column 'secret_info' and a row containing 'sensitive_value_from_template'). For example, using `dbshell` after setting the schema to 'empty':
          ```sql
          CREATE TABLE leaked_data (secret_info VARCHAR(255));
          INSERT INTO leaked_data (secret_info) VALUES ('sensitive_value_from_template');
          ```
        - Create a new tenant creation endpoint in the application if one doesn't exist, or use an existing admin interface to create tenants. Ensure this endpoint is accessible to an attacker (either publicly or after gaining some level of access). Configure tenant creation to use cloning from the 'empty' schema. If using `clone_tenant` management command directly, ensure you can execute it as an attacker (e.g., via compromised admin access).
    2. **Exploit:**
        - As an attacker, use the tenant creation endpoint or command to create a new tenant (e.g., schema name: 'attacker_tenant'), cloning from the 'empty' schema. When using `clone_tenant` command, use:
          ```bash
          python manage.py clone_tenant --clone_from empty --clone_tenant_fields False --schema_name attacker_tenant --name "Attacker Tenant" --domain-domain attacker-tenant.example.com --domain-is_primary True
          ```
        - Log in to the newly created tenant 'attacker_tenant'.
        - Query the database within the 'attacker_tenant' schema to check for the cloned sensitive data. For example, using `dbshell` after setting the schema to 'attacker_tenant':
          ```sql
          SELECT * FROM leaked_data;
          ```
    3. **Verification:**
        - Verify that the 'leaked_data' table and the row with 'sensitive_value_from_template' from the template schema ('empty') are present in the 'attacker_tenant' schema.
        - If the sensitive data is accessible in the new tenant, the vulnerability is confirmed. The query in step 2.2 should return the 'sensitive_value_from_template'.