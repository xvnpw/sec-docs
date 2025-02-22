Here is the combined list of vulnerabilities, formatted as markdown:

## Combined Vulnerability List

### 1. Path Traversal Write via Filename Template

- **Vulnerability Name:** Path Traversal Write via Filename Template / Arbitrary File Path Injection in Backup File Naming
- **Description:**
    - An attacker with administrative privileges (or who has compromised an admin account) can exploit a path traversal vulnerability by manipulating the `DBBACKUP_FILENAME_TEMPLATE` or `DBBACKUP_MEDIA_FILENAME_TEMPLATE` settings. These templates are used to generate backup filenames.
    - Step 1: The attacker gains access to the Django admin panel or any interface that allows modification of Django settings, specifically `DBBACKUP_FILENAME_TEMPLATE` or `DBBACKUP_MEDIA_FILENAME_TEMPLATE`.
    - Step 2: The attacker modifies either `DBBACKUP_FILENAME_TEMPLATE` or `DBBACKUP_MEDIA_FILENAME_TEMPLATE` to include path traversal characters, such as `../`. For example, setting `DBBACKUP_FILENAME_TEMPLATE` to `../../../../tmp/evil_backup_{datetime}.db` or `"../malicious-{datetime}.bak"`.
    - Step 3: The attacker triggers a database or media backup operation, for instance, by using the `dbbackup` or `mediabackup` Django management command.
    - Step 4: The `filename_generate` function in `dbbackup/utils.py` uses the maliciously crafted template to generate the backup filename. Due to the path traversal characters, the backup file will be written to an unintended location on the server's filesystem.
    - Later, when cleanup routines (which use the same filename) run, they may delete files in unintended directories.
- **Impact:**
    - By writing files to arbitrary locations, an attacker could overwrite critical system files, potentially leading to system instability or denial of service.
    - Alternatively, the attacker could write malicious files (e.g., web shells, scripts) to directories accessible by the webserver, potentially leading to arbitrary code execution and full system compromise.
    - By writing backup files outside the controlled directory, an attacker might overwrite or delete critical system files or sensitive application data. This could lead to data loss, denial of service, or even privilege escalation if key files are altered or removed.
- **Vulnerability Rank:** High
- **Currently Implemented Mitigations:**
    - The project includes Django system checks (W007 and W008 in `dbbackup/checks.py`) that issue a warning if the filename templates contain slashes ('/'). These checks are passive warnings during Django's `check` command execution and do not actively prevent path traversal during runtime or enforce input validation.
    - The project implements warning checks in `dbbackup/checks.py` (warnings _W007_ and _W008_) that notify the administrator if the filename templates contain slashes. However, these warnings do not block the use of unsafe templates.
- **Missing Mitigations:**
    - **Input Validation:** The project lacks runtime input validation for `DBBACKUP_FILENAME_TEMPLATE` and `DBBACKUP_MEDIA_FILENAME_TEMPLATE`. It should sanitize or strictly validate these settings to disallow path traversal sequences (e.g., `../`, `..\\`, absolute paths starting with `/` or `C:\`). Enforce strict validation of filename templates (reject templates containing “/”, “\”, or relative path components such as "..").
    - **Path Sanitization:**  While `REG_FILENAME_CLEAN.sub("-", filename)` in `filename_generate` removes redundant hyphens, it does not prevent path traversal sequences. A robust path sanitization function should be implemented to remove or neutralize path traversal components from the generated filename before file system operations. Sanitize or canonicalize the generated file paths to ensure they always reside within a designated safe backup directory.
    - Add configuration validation that prevents unsafe backup path definitions at startup.
- **Preconditions:**
    - Administrative access to the Django application's settings configuration (either through Django admin panel or other configuration interfaces) or the backup filename templates are misconfigured or can be influenced by an attacker (for example, via an exposed administrative interface or unprotected environment variables).
    - The application using `django-dbbackup` must allow modification of `DBBACKUP_FILENAME_TEMPLATE` or `DBBACKUP_MEDIA_FILENAME_TEMPLATE` settings without proper validation.
- **Source Code Analysis:**
    - `dbbackup/settings.py`: Defines `FILENAME_TEMPLATE` and `MEDIA_FILENAME_TEMPLATE` settings, which are read directly from Django's `settings`.
    - `dbbackup/utils.py`: The `filename_generate` function uses these templates to construct the backup filename.
    - `dbbackup/checks.py`: Includes system checks to warn about slashes in templates, but does not enforce validation or prevention.
    - `dbbackup/management/commands/dbbackup.py` & `dbbackup/management/commands/mediabackup.py`: These commands use `utils.filename_generate` to create backup filenames.

    ```python
    # File: dbbackup/management/commands/dbbackup.py
    class Command(BaseDbBackupCommand):
        # ...
        def _save_new_backup(self, database):
            # ...
            # Get backup, schema and name
            filename = self.connector.generate_filename(self.servername) # Filename generated by connector, but template comes from settings
            # ...
            filename = self.filename or filename # Output filename can override generated filename
            # ...
            if self.path is None:
                self.write_to_storage(outputfile, filename) # Write to storage using potentially attacker-controlled filename
            else:
                self.write_local_file(outputfile, self.path) # Write to local path, attacker-controlled path is not used here, but local path might still be misused

    # File: dbbackup/management/commands/mediabackup.py
    class Command(BaseDbBackupCommand):
        # ...
        def backup_mediafiles(self):
            # ...
            if self.filename:
                filename = self.filename # Output filename can override generated filename
            else:
                extension = f"tar{'.gz' if self.compress else ''}"
                filename = utils.filename_generate( # Filename generated using template from settings
                    extension, servername=self.servername, content_type=self.content_type
                )
        # ...
        if self.path is None:
            self.write_to_storage(tarball, filename) # Write to storage using potentially attacker-controlled filename
        else:
            self.write_local_file(tarball, self.path) # Write to local path, attacker-controlled path is not used here, but local path might still be misused
    ```
    - In `dbbackup/utils.py`, the function `filename_generate` retrieves the template from settings and uses it without further sanitization.
    - ```python
      def filename_generate(
          short_name,
          timestamp=None,
          servername=None,
          extension=None,
          template=FILENAME_TEMPLATE, # FILENAME_TEMPLATE is taken from settings
          **kwargs
      ):
          if not timestamp:
              timestamp = timezone.now().strftime("%Y-%m-%d-%H%M%S")
          if not servername:
              servername = socket.gethostname()
          if not extension:
              extension = 'bak'

          filename = template.format( # template is used directly without sanitization
              short_name=short_name,
              timestamp=timestamp,
              servername=servername,
              extension=extension,
              datetime=timestamp, # datetime is also timestamp
              **kwargs
          )
          return filename
      ```
    - Although the helper `_check_filename_template` (called in `dbbackup/checks.py`) flags templates that contain a forward slash, it “only” issues a warning.
    - The resulting filename is later passed directly to file write and delete methods in `dbbackup/storage.py` without additional path validation.
    - The commands `dbbackup` and `mediabackup` use the filename generated by `utils.filename_generate` which uses the potentially vulnerable templates `DBBACKUP_FILENAME_TEMPLATE` and `DBBACKUP_MEDIA_FILENAME_TEMPLATE` from Django settings. If an attacker can modify these settings, they can control the output filename and potentially write files outside the intended backup directory.

- **Security Test Case:**
    1. Set up a Django project using `django-dbbackup`. Ensure you have access to Django admin panel or a similar settings configuration interface.
    2. Log in as a superuser or an administrator who has permissions to modify Django settings.
    3. Navigate to the settings configuration interface for `django-dbbackup`. This might be a custom admin page or direct access to settings.py if applicable for your test setup.
    4. Locate the setting for `DBBACKUP_FILENAME_TEMPLATE` and change its value to: `../../../../tmp/evil_backup_{datetime}.db` or `"../malicious-{datetime}.bak"`.
    5. Execute the database backup command, for example, using Django's `manage.py dbbackup`.
    6. After the backup command completes, check the `/tmp/` directory on the server.
    7. Verify if a file named `evil_backup_<datetime>.db` or a file whose name starts with “malicious-” (with a timestamp in the filename) has been created in the `/tmp/` directory.
    8. If the file exists in `/tmp/`, it confirms the Path Traversal Write vulnerability. The backup file was written outside the intended backup location due to the manipulated filename template.
    9. Optionally, trigger a cleanup command and verify that it deletes files in the unintended location.
    10. Confirm that an attacker could leverage this behavior to overwrite or erase critical files on the server.

### 2. Insecure Backup File Storage Exposure

- **Vulnerability Name:** Insecure Backup File Storage Exposure
- **Description:**
    - By default the project uses a Django storage backend for saving backup files. If the settings `DBBACKUP_STORAGE` and `DBBACKUP_STORAGE_OPTIONS` are not explicitly configured to point to a secured, nonpublic location, the fallback is to use the default `django.core.files.storage.FileSystemStorage`. In many deployments the default storage location may be web‑accessible.
    - An attacker who visits a known URL (or is able to probe for backup files) might be able to download backup files containing sensitive information such as database dumps and media files.
- **Impact:**
    - Sensitive data—including potentially confidential user or application information stored in database backups—can be exposed publicly. This leakage can lead to data breaches, legal repercussions, and reputation damage.
- **Vulnerability Rank:** High
- **Currently Implemented Mitigations:**
    - The project allows administrators to configure both the storage backend and its options via settings. In tests (see `dbbackup/tests/settings.py`), backups are directed to temporary, nonpublic directories. However, the default behavior in production environments may simply fall back to the standard file system storage with no additional access restrictions.
- **Missing Mitigations:**
    - Enforce that backup files are stored by default in a secure, non‑public directory that is inaccessible from the web.
    - Validate storage configuration during application startup, ensuring that file permissions and access controls are correctly set.
    - Consider adding explicit access checks for backup file endpoints if the storage backend is served somehow over HTTP.
- **Preconditions:**
    - The deployment does not override default storage settings (i.e. `DBBACKUP_STORAGE` and `DBBACKUP_STORAGE_OPTIONS`) to point to a secure location, leaving backups stored in a web‑accessible location.
- **Source Code Analysis:**
    - `dbbackup/settings.py`: The code sets the backup `STORAGE` to the value of `DBBACKUP_STORAGE` or falls back to `django.core.files.storage.FileSystemStorage`.
    - ```python
      from django.conf import settings as django_settings
      from django.core.files.storage import FileSystemStorage

      STORAGE = getattr(django_settings, 'DBBACKUP_STORAGE', 'dbbackup.storage.FileSystemStorage') # default is FileSystemStorage
      STORAGE_OPTIONS = getattr(django_settings, 'DBBACKUP_STORAGE_OPTIONS', {})
      ```
    - The `Storage` class in `dbbackup/storage.py` merely instantiates the given storage class and uses it for file operations without adding additional security measures.
    - ```python
      def get_storage(self):
          storage_cls = import_string(settings.STORAGE) # STORAGE from dbbackup.settings
          return storage_cls(**settings.STORAGE_OPTIONS) # STORAGE_OPTIONS from dbbackup.settings
      ```
    - No further restrictions (such as permissions or authentication checks) are applied to the backup file access.

- **Security Test Case:**
    1. Deploy the application with default settings (i.e. without overriding `DBBACKUP_STORAGE` and `DBBACKUP_STORAGE_OPTIONS`).
    2. Run a backup command (for example, `python manage.py dbbackup`) to create a backup file.
    3. Identify the physical location or the URL where the backup file is stored. For `FileSystemStorage` default location is `MEDIA_ROOT`. If `MEDIA_ROOT` is within webserver document root, then files are accessible.
    4. Using a web browser or HTTP client, attempt to access and download the backup file without any credentials. For example, if `MEDIA_URL` is `/media/` and backup file is stored in `MEDIA_ROOT/backups/`, then attacker can try to access `/media/backups/<backup_filename>`.
    5. Confirm that the backup file is accessible and review its contents for sensitive data.

### 3. Potential Subprocess Command Injection in Database Backup Commands

- **Vulnerability Name:** Potential Subprocess Command Injection in Database Backup Commands
- **Description:**
    - The connectors for various databases (e.g. MySQL, PostgreSQL, MongoDB) build shell command strings by concatenating configuration parameters such as database names, hostnames, port numbers, user names, and table names.
    - Although some parameters (e.g. passwords) are run through escaping routines like `utils.get_escaped_command_arg`, many other fields are inserted directly into command strings using f‑strings.
    - If an attacker can tamper with any of these configuration values—through misconfiguration, tainted environment variables, or insecure admin interfaces—they may inject malicious shell commands into the string.
    - For example, if the database name were set to: `dbname; rm -rf /`, the constructed command might include an extra command that executes destructive actions.
- **Impact:**
    - If successful, this vulnerability could allow an attacker to execute arbitrary shell commands on the host. The impact ranges from data exfiltration to complete system compromise, resulting in data destruction or full takeover of the server.
- **Vulnerability Rank:** High
- **Currently Implemented Mitigations:**
    - The code uses `shlex.split` to break the constructed command string into a list before passing it to `subprocess.Popen`, and helper functions (like `get_escaped_command_arg`) are used for certain parameters (e.g. passwords).
    - However, many other parameters (such as the database name, host, port, and table names extracted from `self.exclude`) are concatenated directly without thorough sanitization.
- **Missing Mitigations:**
    - Rigorously validate and sanitize all configuration parameters that are inserted into shell commands.
    - Avoid the use of unsanitized f‑string concatenation for command construction. Prefer to build the command as a list of arguments or use safer subprocess interfaces that do not require shell parsing.
    - Ensure that the application’s configuration cannot be tampered with by external users (for example, by restricting environment variable access or protecting admin interfaces).
- **Preconditions:**
    - An attacker must be able to influence one or more database configuration parameters (even if indirectly through an insecurely managed admin interface or misconfigured environment).
    - The vulnerable command construction logic (in connectors such as those in `dbbackup/db/mysql.py` and `dbbackup/db/postgresql.py`) is executed as part of a backup or restore operation.
- **Source Code Analysis:**
    - **MySQL Connector Example:** In `dbbackup/db/mysql.py`, the `_create_dump` method builds a command string using various settings:
    - ```python
      def _create_dump(self):
          args = [self.dump_cmd] # e.g. ['mysql']
          if self.settings.get('HOST'):
              args += ['-h', self.settings['HOST']] # HOST setting is added without sanitization
          if self.settings.get('PORT'):
              args += ['-P', str(self.settings['PORT'])] # PORT setting is added without sanitization
          if self.settings.get('USER'):
              args += ['-u', self.settings['USER']] # USER setting is added without sanitization
          if self.settings.get('PASSWORD'):
              password = get_escaped_command_arg(self.settings['PASSWORD']) # PASSWORD setting is escaped
              args += ['-p{}'.format(password)]
          args += [self.settings['NAME']] # NAME setting (database name) is added without sanitization
          if self.exclude:
              args += ['--ignore-table={}'.format(self.settings['NAME'] + '.' + table) for table in self.exclude] # table names from exclude are added without sanitization
          if self.include_tables:
              args += self.include_tables

          cmd = args
          process = subprocess.Popen(cmd, env=env, **self.popen_kwargs) # cmd is passed as list to subprocess.Popen
          process.wait()
      ```
      - The database name (`self.settings['NAME']`), HOST, PORT, USER, and table names from `self.exclude` are concatenated directly without thorough sanitization. While the password is escaped using `get_escaped_command_arg`, other parameters are not sanitized.
    - **PostgreSQL Connector Example:** In `dbbackup/db/postgresql.py`, the `create_postgres_uri` function constructs a connection URI:
    - ```python
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
      - The `dbname` variable, derived from `self.settings.get("NAME", "")`, is directly incorporated into the command string without proper sanitization beyond URL encoding for username and password. Similar patterns appear in the PostgreSQL and MongoDB connector implementations.
    - Ultimately, the command is passed as a list to `subprocess.Popen` without using a shell, yet unsanitized input in arguments can still lead to unintended command execution depending on how `mysql`, `pg_dump`, `psql` or other database tools parse arguments.

- **Security Test Case:**
    1. In a controlled test environment, adjust one configuration parameter—for example, set the database name to a value like: `dbname; echo HACKED` (ensure this test is done on a disposable system). This can be achieved via environment variables or Django admin if accessible. For example, setting environment variable `DBBACKUP_DATABASE_NAME="dbname; echo HACKED"` might influence database name.
    2. Run the backup command that uses this configuration (e.g., `python manage.py dbbackup`).
    3. Monitor the executed command output or the system logs to detect whether the additional command fragment (e.g. “HACKED”) was executed outside the intended backup command context. Redirecting standard output and standard error of the backup command to files can help in monitoring.
    4. Repeat with other parameters (such as elements in the exclusion list, HOST, PORT, USER) to confirm that unsanitized input can lead to the execution of arbitrary commands. Check if injecting options like `-v` or `--help` still works and if it's possible to inject more dangerous options or commands.

    **Example Test Case for PostgreSQL Command Injection via Database Name:**

    1. **Step 1:** Modify Django settings to set a malicious database name. In `dbbackup/tests/settings.py`, add or modify the `DATABASES` setting to include a database with a malicious name:
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
    2. **Step 2:** Execute the `dbbackup` management command, targeting the vulndb database:
    ```bash
    python manage.py dbbackup --database=vulndb
    ```
    3. **Step 3:** Check for command execution. After running the command, check if the file `/tmp/pwned_db_name` has been created on the server.
    ```bash
    ls -l /tmp/pwned_db_name
    ```
    4. If the file `/tmp/pwned_db_name` exists, it indicates that the command injection vulnerability is present in `dbbackup` command.
    5. **Step 4:** Execute the `dbrestore` management command, targeting the vulndb database:
    ```bash
    python manage.py dbrestore --database=vulndb
    ```
    6. **Step 5:** Check for command execution. After running the command, check if the file `/tmp/pwned_db_name` has been created on the server.
    ```bash
    ls -l /tmp/pwned_db_name
    ```
    7. If the file `/tmp/pwned_db_name` exists, it indicates that the command injection vulnerability is present in `dbrestore` command as well.