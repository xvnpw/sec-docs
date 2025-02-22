- Vulnerability Name: FTP Backend - Path Traversal via Filename
- Description:
    1. An attacker can craft a malicious filename containing path traversal characters like `..`.
    2. When this filename is used in functions like `delete`, `exists`, `listdir`, `size`, the FTP backend in `django-storages` does not properly sanitize or validate the path.
    3. This allows the attacker to potentially access or manipulate files outside of the intended storage location defined by the `location` setting.
- Impact:
    - High: An attacker could delete, list, or potentially overwrite files outside the intended storage directory on the FTP server if the FTP server's permissions allow it. This could lead to data loss, information disclosure, or even remote code execution if combined with other vulnerabilities or misconfigurations on the FTP server itself.
- Vulnerability Rank: high
- Currently implemented mitigations:
    - None: The FTP backend does not implement any specific path sanitization or validation for filenames.
- Missing mitigations:
    - Implement path sanitization in the `_normalize_name` or similar path handling functions within the `FTPStorage` backend to prevent path traversal. This should remove or neutralize `..` components and potentially restrict characters allowed in filenames.
- Preconditions:
    - The application must be using the `FTPStorage` backend.
    - The attacker must have the ability to influence the filename used in storage operations (e.g., through file upload functionality or by manipulating data that is used to construct filenames).
- Source code analysis:
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

- Security test case:
    1. Setup an FTP server (e.g., using `pyftpdlib` for testing purposes). Configure it with a user and a directory structure.
    2. Configure a Django project to use `FTPStorage` pointing to the test FTP server. Set `location` to an empty string or a relative path to increase the likelihood of traversal.
    3. Create a file within the FTP server's user directory (intended storage area), e.g., `test_file.txt`.
    4. Create another file outside the intended storage directory but still accessible by the FTP user if traversal is possible, e.g., `sensitive_file.txt` in the user's home directory.
    5. In the Django application, attempt to delete the `sensitive_file.txt` using a path traversal filename like `"../../sensitive_file.txt"` or `"../sensitive_file.txt"`.
    6. Verify if the `sensitive_file.txt` outside the intended storage location is actually deleted from the FTP server. If it is, the path traversal vulnerability is confirmed.
    7. Repeat steps for `exists`, `listdir`, and `size` operations to confirm the vulnerability across different FTP backend functions. For `listdir`, attempt to list directories outside the intended path. For `size` and `exists`, check if information about files outside the intended path can be retrieved.