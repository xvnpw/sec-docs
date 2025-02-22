## Vulnerability List

- Vulnerability Name: FTP Backend - Plaintext Credentials in URL Location
- Description:
    1. The `FTPStorage` backend allows specifying the FTP server location via a URL string.
    2. This URL can include the username and password directly within the URL itself (e.g., `ftp://user:password@host:port/`).
    3. If a developer configures `FTPStorage` using a URL with embedded credentials, these credentials will be stored in plaintext in the Django settings.
    4. An attacker gaining access to the Django settings (e.g., via configuration file exposure, settings variable leakage, or code repository access) can retrieve the FTP credentials in plaintext.
    5. The attacker can then use these credentials to access the FTP server, potentially reading, writing, or deleting files stored there, depending on the FTP server's permissions.
- Impact:
    - High: Exposure of FTP credentials allows unauthorized access to the FTP server. This can lead to data breaches (reading sensitive files), data manipulation (modifying or deleting files), and potentially further compromise of systems if the FTP server is connected to other internal networks or systems.
- Vulnerability Rank: High
- Currently Implemented Mitigations:
    - None: The code explicitly parses and uses the credentials from the URL if provided.
- Missing Mitigations:
    - **Do not store credentials in URL:** The application should discourage or explicitly prevent users from storing FTP credentials directly in the URL.
    - **Configuration via separate settings:**  Credentials (username, password, host, port) should be configured via separate Django settings variables instead of embedding them in a single URL string. This allows for more secure configuration methods like environment variables or secret management tools.
    - **Documentation:** The documentation should strongly warn against including credentials in the URL and recommend using separate settings for credentials.
- Preconditions:
    - The application uses the `FTPStorage` backend.
    - The `FTPStorage` `location` setting is configured using a URL that includes username and password in the URL string.
    - An attacker gains access to the Django settings where the `FTPStorage` `location` setting is stored.
- Source Code Analysis:
    1. File: `/code/storages/backends/ftp.py`
    2. Function: `_decode_location(self, location)`
    3. Line:
       ```python
       splitted_url = re.search(
            r"^(?P<scheme>.+)://(?P<user>.+):(?P<passwd>.+)@(?P<host>.+):(?P<port>\d+)/(?P<path>.*)$",
            location,
        )
       ```
       This line uses a regular expression to parse the provided `location` string as a URL. It extracts named groups for scheme, user, password, host, port, and path from the URL.
    4. Lines:
       ```python
       config = {}
        config["active"] = splitted_url["scheme"] == "aftp"
        config["secure"] = splitted_url["scheme"] == "ftps"

        config["path"] = splitted_url["path"] or "/"
        config["host"] = splitted_url["host"]
        config["user"] = splitted_url["user"]
        config["passwd"] = splitted_url["passwd"]
        config["port"] = int(splitted_url["port"])
       ```
       These lines extract the username and password directly from the parsed URL (`splitted_url["user"]`, `splitted_url["passwd"]`) and store them in the `config` dictionary. These extracted credentials are then used to establish the FTP connection in the `_start_connection` method.
    5. Visualization:

    ```mermaid
    graph LR
        A[Developer Configures FTPStorage with URL in settings.py] --> B(FTPStorage._decode_location parses URL using regex);
        B --> C{URL matches regex with username and password?};
        C -- Yes --> D[Extract username and password from URL using regex groups];
        D --> E[Store credentials in FTPStorage config];
        E --> F[Credentials stored in plaintext in Django settings];
        F --> G[Attacker Accesses Django Settings];
        G --> H[Attacker retrieves plaintext FTP credentials];
        H --> I[Attacker uses credentials to access FTP server];
    ```
- Security Test Case:
    1. **Setup:**
        - Configure a Django project to use `django-storages`.
        - In `settings.py`, configure `DEFAULT_FILE_STORAGE` to use `storages.backends.ftp.FTPStorage`.
        - Set `FTP_STORAGE_LOCATION` to a URL string that includes a username and password for a test FTP server (e.g., `ftp://testuser:testpassword@localhost:2121/`).
        - Start a dummy FTP server (e.g., using `pyftpdlib`) for testing purposes.
    2. **Access Settings:**
        - Simulate an attacker gaining access to the Django settings. This can be achieved by:
            - Directly inspecting the `settings.py` file if accessible (e.g., in a development environment or due to misconfiguration).
            - Programmatically accessing the settings within the running Django application if an information disclosure vulnerability exists elsewhere.
    3. **Extract Credentials:**
        - In the simulated attacker scenario, retrieve the value of `FTP_STORAGE_LOCATION` from the Django settings.
        - Parse the `FTP_STORAGE_LOCATION` URL and extract the username and password components.
    4. **FTP Login:**
        - Using the extracted username and password, attempt to connect to the configured FTP server (e.g., using a standard FTP client or programmatically with `ftplib`).
    5. **Verify Access:**
        - If the connection is successful, the attacker has successfully obtained and used the plaintext FTP credentials. List files or perform other actions on the FTP server to confirm unauthorized access.
    6. **Expected Result:** The attacker should be able to successfully connect to the FTP server using the extracted credentials, proving the vulnerability.