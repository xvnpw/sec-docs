## Vulnerability List

### 1. Potential Command Injection in PostgreSQL Connector via Database Name

- **Description:**
    - The `django-dbbackup` project uses `pg_dump` and `psql` command-line utilities for backing up and restoring PostgreSQL databases.
    - In the `dbbackup/db/postgresql.py` file, the `create_postgres_uri` function constructs a connection URI for these utilities using database settings.
    - This function uses `urllib.parse.quote` to properly encode the username and password for the URI.
    - However, the database name (`dbname`) is directly incorporated into the command string without proper sanitization.
    - If an attacker could somehow control the database name setting within Django's configuration (which is generally not directly achievable for external attackers in typical deployments, but could be a risk in case of misconfigurations or other vulnerabilities that allow settings modification), they could inject malicious shell commands.
    - For example, if the database name is maliciously set to `"; touch /tmp/pwned #"`, the constructed command might execute the injected `touch` command.
    - This vulnerability affects both database backup (`dbbackup`) and database restore (`dbrestore`) commands as they both utilize the vulnerable `create_postgres_uri` function.
    - Step-by-step trigger instructions:
        1. An attacker gains unauthorized access to Django's settings and modifies the `NAME` setting for a PostgreSQL database to a malicious value, such as `"; touch /tmp/pwned #"`.
        2. An administrator or an automated process within the application executes a database backup or restore command using `django-dbbackup` (e.g., `python manage.py dbbackup` or `python manage.py dbrestore`).
        3. The `create_postgres_uri` function within `dbbackup/db/postgresql.py` is called, which constructs a command string that includes the malicious database name.
        4. When `pg_dump` or `psql` is executed using `subprocess.Popen`, the injected command `; touch /tmp/pwned #` is also executed by the shell.

- **Impact:**
    - High. Successful command injection can lead to arbitrary command execution on the server hosting the Django application.
    - An attacker could potentially gain full control of the server, read sensitive data, modify application data, or cause further harm.

- **Vulnerability Rank:** High

- **Currently Implemented Mitigations:**
    - Partial. The project uses `urllib.parse.quote` to encode the username and password in the PostgreSQL URI, which mitigates injection through these credentials.
    - File: `/code/dbbackup/db/postgresql.py`
    - Function: `create_postgres_uri`

- **Missing Mitigations:**
    - Input sanitization for the database name (`dbname`) and potentially host (`host`) parameters in the `create_postgres_uri` function within `dbbackup/db/postgresql.py`.
    - All components used to construct the command string should be properly escaped or constructed programmatically to prevent shell injection. Using parameterized queries or similar secure command construction methods for external commands would be beneficial.

- **Preconditions:**
    - An attacker needs to be able to modify the Django application's database settings, specifically the `NAME` setting for a PostgreSQL database. This is typically not directly possible for an external attacker in a properly secured environment. However, this vulnerability becomes critical if combined with other vulnerabilities that allow for configuration modification.

- **Source Code Analysis:**
    - File: `/code/dbbackup/db/postgresql.py`
    - Function: `create_postgres_uri(self)`
    ```python
    def create_postgres_uri(self):
        host = self.settings.get("HOST", "localhost")
        dbname = self.settings.get("NAME", "")
        user = quote(self.settings.get("USER") or "")
        password = self.settings.get("PASSWORD", "")
        password = f":{quote(password)}" if password else ""
        if not user:
            password = ""
        else:
            host = "@" + host

        port = ":{}".format(self.settings.get("PORT")) if self.settings.get("PORT") else ""
        dbname = f"--dbname=postgresql://{user}{password}{host}{port}/{dbname}"
        return dbname
    ```
    - Visualization:
        ```
        settings['NAME'] (Unsanitized Input) --> dbname variable --> Command String (Unsanitized) --> subprocess.Popen --> Shell Command Execution (VULNERABILITY)
        ```
    - The `dbname` variable is directly formatted into the command string without any sanitization beyond URL encoding for username and password. If `settings['NAME']` contains shell metacharacters, they will be interpreted by the shell when `subprocess.Popen` executes the command.
    - This code is used in `dbbackup/db/postgresql.py` and indirectly used by `dbbackup.management.commands.dbbackup` and `dbbackup.management.commands.dbrestore` commands.

- **Security Test Case:**
    - **Step 1:** Modify Django settings to set a malicious database name. In `dbbackup/tests/settings.py`, add or modify the `DATABASES` setting to include a database with a malicious name:
    ```python
    DATABASES = {
        'default': {
            'ENGINE': os.environ.get('DB_ENGINE', 'django.db.backends.sqlite3'),
            'NAME': os.environ.get('DB_NAME', ':memory:'),
            # ... other settings
        },
        'vulndb': {  # Add a new database with a malicious name
            'ENGINE': 'django.db.backends.postgresql', # or 'django.contrib.gis.db.backends.postgis'
            'NAME': '"; touch /tmp/pwned_db_name #"', # Malicious database name
            'USER': 'testuser',
            'PASSWORD': 'testpassword',
            'HOST': 'localhost',
        }
    }
    ```
    - **Step 2:** Execute the `dbbackup` management command, targeting the vulndb database:
    ```bash
    python manage.py dbbackup --database=vulndb
    ```
    - **Step 3:** Check for command execution. After running the command, check if the file `/tmp/pwned_db_name` has been created on the server.
    ```bash
    ls -l /tmp/pwned_db_name
    ```
    - If the file `/tmp/pwned_db_name` exists, it indicates that the command injection vulnerability is present in `dbbackup` command.
    - **Step 4:** Execute the `dbrestore` management command, targeting the vulndb database:
    ```bash
    python manage.py dbrestore --database=vulndb
    ```
    - **Step 5:** Check for command execution. After running the command, check if the file `/tmp/pwned_db_name` has been created on the server.
    ```bash
    ls -l /tmp/pwned_db_name
    ```
    - If the file `/tmp/pwned_db_name` exists, it indicates that the command injection vulnerability is present in `dbrestore` command as well.