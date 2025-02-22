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