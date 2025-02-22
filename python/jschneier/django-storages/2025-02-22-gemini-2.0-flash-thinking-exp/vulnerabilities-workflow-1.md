Combining Vulnerability Lists:

This document consolidates vulnerabilities identified in FTP and SFTP storage backends. Each vulnerability is detailed below, outlining the description, impact, mitigation strategies, preconditions, code analysis, and security test cases.

### FTP Backend - Plaintext Credentials in URL Location

- **Description:**
    1. The `FTPStorage` backend allows specifying the FTP server location via a URL string.
    2. This URL can include the username and password directly within the URL itself (e.g., `ftp://user:password@host:port/`).
    3. If a developer configures `FTPStorage` using a URL with embedded credentials, these credentials will be stored in plaintext in the Django settings.
    4. An attacker gaining access to the Django settings (e.g., via configuration file exposure, settings variable leakage, or code repository access) can retrieve the FTP credentials in plaintext.
    5. The attacker can then use these credentials to access the FTP server, potentially reading, writing, or deleting files stored there, depending on the FTP server's permissions.
- **Impact:**
    - High: Exposure of FTP credentials allows unauthorized access to the FTP server. This can lead to data breaches (reading sensitive files), data manipulation (modifying or deleting files), and potentially further compromise of systems if the FTP server is connected to other internal networks or systems.
- **Vulnerability Rank:** High
- **Currently Implemented Mitigations:**
    - None: The code explicitly parses and uses the credentials from the URL if provided.
- **Missing Mitigations:**
    - **Do not store credentials in URL:** The application should discourage or explicitly prevent users from storing FTP credentials directly in the URL.
    - **Configuration via separate settings:**  Credentials (username, password, host, port) should be configured via separate Django settings variables instead of embedding them in a single URL string. This allows for more secure configuration methods like environment variables or secret management tools.
    - **Documentation:** The documentation should strongly warn against including credentials in the URL and recommend using separate settings for credentials.
- **Preconditions:**
    - The application uses the `FTPStorage` backend.
    - The `FTPStorage` `location` setting is configured using a URL that includes username and password in the URL string.
    - An attacker gains access to the Django settings where the `FTPStorage` `location` setting is stored.
- **Source Code Analysis:**
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
- **Security Test Case:**
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

### Insecure FTP TLS Connection Without Certificate Validation

- **Vulnerability Name:** Insecure FTP TLS Connection Without Certificate Validation
- **Description:**
    - In the FTP storage backend (see `storages/backends/ftp.py`), when a storage URL uses the “ftps://” scheme the code instantiates Python’s `ftplib.FTP_TLS` and calls `prot_p()` on the connection.
    - However, no custom SSL context is created or provided to enforce certificate verification.
    - An external attacker who can position themselves along the network path (for example, on an untrusted Wi‑Fi hotspot or a compromised network node) can intercept the TLS handshake and substitute a forged or self‑signed certificate.
    - With no certificate verification in place, the client accepts the malicious certificate and proceeds with login and file transfer operations.
- **Impact:**
    - FTP credentials (username and password) and file data transmitted over the connection may be exposed to the attacker.
    - The integrity of file transfers is compromised, potentially allowing further tampering or man‑in‑the-middle attacks.
- **Vulnerability Rank:** High
- **Currently Implemented Mitigations:**
    - The backend does use `ftplib.FTP_TLS()` when the “ftps://” scheme is used and calls `prot_p()` to encrypt the data channel.
    - No further measures (such as creating a custom SSL context with certificate validation enabled) are taken.
- **Missing Mitigations:**
    - An SSL context (for example, created via `ssl.create_default_context()`) should be instantiated and passed to enforce proper certificate verification.
    - Configuration options should be introduced so deployments can require that only valid server certificates are accepted.
- **Preconditions:**
    - The application must be configured to use FTPS (i.e. the storage location URL starts with “ftps://”).
    - An attacker must be able to intercept or tamper with the network traffic between the application and the FTP server.
- **Source Code Analysis:**
    - In `storages/backends/ftp.py`, inside the connection initialization routine (`_start_connection()`), the following steps occur:
      - The code checks if secure mode is enabled by inspecting `self._config["secure"]`.
      - It creates a connection using `ftp = ftplib.FTP_TLS()` if secure mode is requested; otherwise it falls back to `ftplib.FTP()`.
      - After connecting, it sets the FTP encoding and logs in using credentials from configuration.
      - For secure mode, `ftp.prot_p()` is called to enable data channel encryption.
      - No custom SSL context is created or provided—thus the default behavior accepts any certificate without validation.
- **Security Test Case:**
    1. Set up an FTPS server that presents a self‑signed or invalid certificate.
    2. Configure the Django application to use the FTPS backend by setting the storage location URL to something like:
       `ftps://user:pass@your.ftps.server:port/path`
    3. Place a man‑in‑the‑middle proxy (e.g. mitmproxy) between the application and the FTPS server.
    4. Initiate a file upload or download operation from the application and observe that the connection is successfully established despite the invalid certificate.
    5. Capture the network traffic and verify that credentials and file data are transmitted over the encrypted channel, despite the certificate being unverified.
    6. Confirm that when the backend is modified to pass an SSL context with certificate verification enabled, the connection fails with an appropriate certificate error.

### Directory Traversal in SFTP Storage Backend

- **Vulnerability Name:** Directory Traversal in SFTP Storage Backend
- **Description:**
    - In the SFTP storage backend (located in `storages/backends/sftpstorage.py`), remote file paths are generated using a simple join:
      ```python
      def _remote_path(self, name):
          return posixpath.join(self.root_path, name)
      ```
    - No sanitization or normalization is performed on the supplied file name.
    - An attacker who can influence the file name (for example, through a file upload field or similar input) may insert directory traversal sequences such as `../`.
    - For instance, if a file is uploaded with the name `../malicious.txt`, the resulting remote path could resolve outside the intended storage directory.
- **Impact:**
    - An attacker may be able to read, overwrite, or delete files outside the designated directory on the remote SFTP server.
    - This could lead to unauthorized data access, unexpected file modifications, or further system compromise if critical files are targeted.
- **Vulnerability Rank:** High
- **Currently Implemented Mitigations:**
    - The backend relies on a configured `root_path` to segregate file storage but does not validate the file name against directory traversal; it is simply joined with `root_path`.
- **Missing Mitigations:**
    - The backend should sanitize and normalize user‑supplied file names. For example, it could use a ‘safe join’ utility—similar to how other backends (such as the Google Cloud Storage backend) use `safe_join`—to ensure that the resultant path remains within `root_path`.
    - Alternatively, file names containing directory traversal patterns (such as “..”) should be outright rejected.
- **Preconditions:**
    - The application is configured to use the SFTPStorage backend with a defined `root_path`.
    - The application accepts file names (or derives them otherwise) without additional sanitization.
- **Source Code Analysis:**
    - In `storages/backends/sftpstorage.py`, the private method for computing the remote path is implemented as follows:
      ```python
      def _remote_path(self, name):
          return posixpath.join(self.root_path, name)
      ```
    - There is no logic to remove or reject elements like `".."` in the supplied `name`.
    - As a result, even though the backend intends to confine operations to `root_path`, a malicious input can “escape” this folder.
- **Security Test Case:**
    1. Configure the SFTPStorage backend in the Django settings with a fixed `root_path` (for example, `/uploads`).
    2. Use the application’s file upload functionality to attempt to upload a file with a name like `../malicious.txt`.
    3. Monitor the SFTP server (either via logging or manual inspection) and verify that the computed remote path escapes `/uploads` (e.g. resolves as `/malicious.txt`).
    4. Attempt to access or overwrite sensitive files on the SFTP server using this mechanism.
    5. Confirm that introducing proper input validation (for example, by using a safe join function that rejects traversal patterns) prevents the attack.

### FTP Backend - Path Traversal via Filename

- **Vulnerability Name:** FTP Backend - Path Traversal via Filename
- **Description:**
    1. An attacker can craft a malicious filename containing path traversal characters like `..`.
    2. When this filename is used in functions like `delete`, `exists`, `listdir`, `size`, the FTP backend in `django-storages` does not properly sanitize or validate the path.
    3. This allows the attacker to potentially access or manipulate files outside of the intended storage location defined by the `location` setting.
- **Impact:**
    - High: An attacker could delete, list, or potentially overwrite files outside the intended storage directory on the FTP server if the FTP server's permissions allow it. This could lead to data loss, information disclosure, or even remote code execution if combined with other vulnerabilities or misconfigurations on the FTP server itself.
- **Vulnerability Rank:** High
- **Currently Implemented Mitigations:**
    - None: The FTP backend does not implement any specific path sanitization or validation for filenames.
- **Missing Mitigations:**
    - Implement path sanitization in the `_normalize_name` or similar path handling functions within the `FTPStorage` backend to prevent path traversal. This should remove or neutralize `..` components and potentially restrict characters allowed in filenames.
- **Preconditions:**
    - The application must be using the `FTPStorage` backend.
    - The attacker must have the ability to influence the filename used in storage operations (e.g., through file upload functionality or by manipulating data that is used to construct filenames).
- **Source Code Analysis:**
    - File: `/code/storages/backends/ftp.py`
    - The `FTPStorage` backend uses `ftplib` for FTP operations.
    - The `_normalize_name` method in `FTPStorage` (and its parent classes) doesn't perform sufficient path sanitization to prevent traversal. It relies on `storages.utils.safe_join` which is designed for S3 paths and may not be effective for FTP in the same way, or is not used correctly in all relevant FTP backend methods.
    - Let's examine the `delete` function as an example:
        ```python
        def delete(self, name):
            if not name:
                return
            self._connect()
            try:
                self.sftp.delete(self._normalize_name(name)) # Potential path traversal here
            except IOError as e:
                raise FTPStorageException(e)
            finally:
                self.disconnect()
        ```
        - The `_normalize_name(name)` function is called before passing the name to `sftp.delete`. Let's look at `_normalize_name`:
        ```python
        def _normalize_name(self, name):
            return safe_join(self.location, name).replace("\\", "/")
        ```
        - `safe_join` from `storages.utils` is used. Let's examine `safe_join` in `/code/storages/utils.py`:
        ```python
        def safe_join(base, *paths):
            # ... (omitted for brevity - see file content provided) ...
            if not final_path.startswith(base_path) or final_path[base_path_len] != "/":
                raise ValueError(
                    "the joined path is located outside of the base path component"
                )
            return final_path.lstrip("/")
        ```
        - `safe_join` is intended to prevent traversal *out* of the `base` directory. However, if `self.location` in `FTPStorage` is not properly set or if the FTP server itself interprets paths differently than `safe_join` expects (e.g., relative to the user's home directory instead of an absolute path), traversal might still be possible.  Furthermore, if `location` is empty, `safe_join` might not effectively restrict paths.
        - The `FTPStorage` backend does not have specific input validation for filenames beyond what `safe_join` provides.
    - Visualization:
        ```
        Attacker Filename: "../../sensitive_file.txt"
        -> _normalize_name(filename) -> safe_join(FTPStorage.location, "../../sensitive_file.txt")
        -> If FTPStorage.location is "", safe_join might return "../sensitive_file.txt" or similar
        -> sftp.delete("../sensitive_file.txt") -> FTP server attempts to delete file potentially outside intended location
        ```

- **Security Test Case:**
    1. Setup an FTP server (e.g., using `pyftpdlib` for testing purposes). Configure it with a user and a directory structure.
    2. Configure a Django project to use `FTPStorage` pointing to the test FTP server. Set `location` to an empty string or a relative path to increase the likelihood of traversal.
    3. Create a file within the FTP server's user directory (intended storage area), e.g., `test_file.txt`.
    4. Create another file outside the intended storage directory but still accessible by the FTP user if traversal is possible, e.g., `sensitive_file.txt` in the user's home directory.
    5. In the Django application, attempt to delete the `sensitive_file.txt` using a path traversal filename like `"../../sensitive_file.txt"` or `"../sensitive_file.txt"`.
    6. Verify if the `sensitive_file.txt` outside the intended storage location is actually deleted from the FTP server. If it is, the path traversal vulnerability is confirmed.
    7. Repeat steps for `exists`, `listdir`, and `size` operations to confirm the vulnerability across different FTP backend functions. For `listdir`, attempt to list directories outside the intended path. For `size` and `exists`, check if information about files outside the intended path can be retrieved.