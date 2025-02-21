- **Vulnerability Name:** Insecure Debug Mode Enabled with Hardcoded Secret Key in Django Settings  
  - **Description:**  
    The file `t/proj/settings.py` sets the Django configuration to development mode by hardcoding a secret key and turning on debugging. In particular, the settings file contains:
    - A hardcoded secret key:  
      `SECRET_KEY = 'u($kbs9$irs0)436gbo9%!b&#zyd&70tx!n7!i&fl6qun@z1_l'`
    - Debug mode enabled:  
      `DEBUG = True`
    - An empty allowed hosts list:  
      `ALLOWED_HOSTS = []`
      
    An external attacker can deliberately trigger an error (for example, by visiting a non-existent URL) to force Django to render its detailed debug error page. This page may reveal sensitive internal configuration details, the secret key, stack traces, and other debugging information.
    
  - **Impact:**  
    - Exposure of sensitive information and system configuration details.
    - Potential leakage of the secret key, which can facilitate further attacks such as session tampering or forging.
    - Full insight into application internals may aid in subsequent exploitation steps.
    
  - **Vulnerability Rank:** Critical
  
  - **Currently Implemented Mitigations:**  
    - _None._ The settings file shows a clear development configuration that is not altered at runtime.
    
  - **Missing Mitigations:**  
    - Set `DEBUG = False` in production.
    - Supply the secret key via secure environment variables rather than hardcoding.
    - Populate an explicit list in `ALLOWED_HOSTS` to restrict which hosts may serve the application.
    
  - **Preconditions:**  
    - The application is deployed (or accidentally left) in a configuration that uses the included settings file as is.
    - The instance is publicly accessible so that error pages can be triggered.
    
  - **Source Code Analysis:**  
    - In `/code/t/proj/settings.py` the following lines are found:
      - `SECRET_KEY = 'u($kbs9$irs0)436gbo9%!b&#zyd&70tx!n7!i&fl6qun@z1_l'`
      - `DEBUG = True`
      - `ALLOWED_HOSTS = []`
    - When `DEBUG=True`, Django will render detailed error pages that include sensitive debugging information if an error is encountered.
    
  - **Security Test Case:**  
    1. Deploy the application (for example, by running the provided Docker configuration) using the current settings.
    2. Navigate in a web browser to a URL that is not defined (e.g., `http://<your-domain>/nonexistent`).
    3. Observe the error page—if it displays a full stack trace and internal configuration (such as the secret key), then the vulnerability is confirmed.
    4. Verify that no secure production settings override these debug parameters.

- **Vulnerability Name:** Default Superuser Credentials Created via Docker Entrypoint  
  - **Description:**  
    The Docker entrypoint script for the Django container (`docker/django/entrypoint.sh`) instructs Django to automatically create a superuser using fixed credentials. The command executed is:
    ```
    python3 manage.py createsuperuserwithpassword \
            --username admin \
            --password admin \
            --email admin@example.org \
            --preserve
    ```
    This hardcoding of credentials means that every deployment using this Docker image will create (or preserve) an administrator account with the username `admin` and the password `admin`.
    
  - **Impact:**  
    - An attacker can access the Django admin interface (usually offered under `/admin`) using these default credentials.
    - Once authenticated, the attacker may perform administrative actions such as modifying tasks, scheduling jobs, or even altering application configurations.
    
  - **Vulnerability Rank:** Critical
  
  - **Currently Implemented Mitigations:**  
    - _None._ The script directly creates the superuser with weak, predictable credentials.
    
  - **Missing Mitigations:**  
    - Remove or disable automatic superuser creation in production.
    - Require credentials to be provided through secure environment variables.
    - Enforce robust password policies for administrative accounts.
    
  - **Preconditions:**  
    - The application is deployed using the provided Docker setup.
    - The Django admin interface is reachable by an external attacker.
    
  - **Source Code Analysis:**  
    - In `/code/docker/django/entrypoint.sh`, the command:
      ```
      python3 manage.py createsuperuserwithpassword \
              --username admin \
              --password admin \
              --email admin@example.org \
              --preserve
      ```
      is executed at startup. This guarantees that the admin account is created with the default username "admin" and password "admin" regardless of any other configuration.
    
  - **Security Test Case:**  
    1. Deploy the Docker container using the provided configuration.
    2. Access the Django admin page (typically at `http://<host>:<port>/admin`).
    3. Attempt to log in using the credentials:
       - Username: `admin`
       - Password: `admin`
    4. Confirm that the admin login succeeds and that full administrative capabilities are available.

- **Vulnerability Name:** Hardcoded Database Credentials in Docker Configuration  
  - **Description:**  
    The Docker base image build steps include a command that appends database configuration settings to the Django settings file. This configuration embeds database credentials directly into the source code. For example, the command in `/code/docker/base/Dockerfile` includes:
    ```
    RUN echo 'DATABASES = {"default": {"ENGINE": "django.db.backends.postgresql", "NAME": "postgres", "USER": "postgres","PASSWORD": "s3cr3t", "HOST": "postgres", "PORT": 5432}}' >> mysite/settings.py
    ```
    This hardcoded credential (password: `s3cr3t`) is then used by the application to connect to the PostgreSQL database.
    
  - **Impact:**  
    - If an attacker is able to access the Docker image or the internal network where the database is running, they can use these credentials to gain unauthorized access to the database.
    - This could lead to data exfiltration, data manipulation, or complete compromise of the stored data.
    
  - **Vulnerability Rank:** High
  
  - **Currently Implemented Mitigations:**  
    - _None._ The credentials are statically written into the settings by the Docker build process.
    
  - **Missing Mitigations:**  
    - Use environment variables or a dedicated secrets management system to inject database credentials at runtime.
    - Avoid hardcoding sensitive information like database passwords in Dockerfiles or in the source repository.
    
  - **Preconditions:**  
    - The application is deployed using the provided Docker configuration.
    - The PostgreSQL database service (and the network configuration) is such that an attacker can connect to it.
    
  - **Source Code Analysis:**  
    - In `/code/docker/base/Dockerfile`, observe the command:
      ```
      RUN echo 'DATABASES = {"default": {"ENGINE": "django.db.backends.postgresql", "NAME": "postgres", "USER": "postgres","PASSWORD": "s3cr3t", "HOST": "postgres", "PORT": 5432}}' >> mysite/settings.py
      ```
      This directly appends a database configuration into `mysite/settings.py` with a hardcoded password.
    
  - **Security Test Case:**  
    1. Deploy the Docker containers using the provided configuration.
    2. Determine how the PostgreSQL service is exposed (verify host/port settings, e.g., via Docker networking).
    3. From a system that has network access to the database server, attempt to connect using the following credentials:
       - Username: `postgres`
       - Password: `s3cr3t`
       - Database: `postgres`
    4. Verify that the connection is successful and that the database contents can be read or manipulated.