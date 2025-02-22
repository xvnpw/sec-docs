- **Vulnerability Name:** Unsafe Deserialization in Migration (Pickle-Based)

  - **Description:**  
    During the migration process in the file `constance/migrations/0003_drop_pickle.py`, the code attempts to “migrate” legacy configuration values that were stored using pickle. For each record whose value is not already in JSON format, the migration decodes a base64‑encoded string and immediately passes it to Python’s built-in `pickle.loads` without any additional verification or sanitization.  
    **Step‑by-step triggering:**  
    1. An attacker who has obtained write access to the Constance configuration (for example, via an exposed or misconfigured database) replaces the stored value with a malicious pickle payload encoded in base64.  
    2. When a site administrator later runs the migration (or when migrations are automatically applied during deployment), the migration code enters the record, determines that its value is not already migrated, and then calls:  
       – `b64decode(constance.value.encode())`  
       – followed by `pickle.loads(…)`  
    3. The attacker’s malicious payload is unpickled and its payload code executes with the privileges of the migration process.
  
  - **Impact:**  
    This issue can lead to full remote code execution (RCE) on the host system, as the malicious pickle payload may execute arbitrary code. An attacker who is able to inject such data may compromise the entire server.
  
  - **Vulnerability Rank:**  
    Critical
  
  - **Currently Implemented Mitigations:**  
    The migration checks whether the stored value is already in JSON format (using a simple check in `is_already_migrated`), but it does not validate or restrict the content that is passed to `pickle.loads`.
  
  - **Missing Mitigations:**  
    • Avoid using `pickle` for deserialization of untrusted data.  
    • Validate and reject non‐JSON (or non‐expected) content in the Constance records before deserialization.  
    • Limit database write access or secure access to the Constance table so that an external attacker cannot inject malicious payloads.  
    • Consider an explicit upgrade path that (a) transforms pickled data in a controlled environment and (b) then permanently disallows untrusted pickle deserialization.
  
  - **Preconditions:**  
    • The attacker must have the ability to modify configuration records (for example, if the database is exposed, misconfigured, or accessible via another exploited vulnerability).  
    • Later, someone (or an automated process) must run the migrations so that the unsafe deserialization is triggered.
  
  - **Source Code Analysis:**  
    • In `constance/migrations/0003_drop_pickle.py`, the function `migrate_pickled_data` iterates over Constance records that have a non‑null `value`.  
    • It calls the helper `is_already_migrated(value)` to decide if the stored value is in JSON format. This check only inspects whether the JSON–decoded object has exactly the keys `{"__type__", "__value__"}`.  
    • For records that are not “migrated,” the code does:  
      `constance.value = dumps(pickle.loads(b64decode(constance.value.encode())))`  
    • There is no validation or sandboxing of the result returned from `pickle.loads`, so a malicious payload would be executed immediately.
  
  - **Security Test Case:**  
    1. In a safe, controlled test environment, manually insert (or simulate insertion of) a Constance record whose `value` field is set to a base64‑encoded malicious pickle payload (the payload can be crafted to perform a harmless action such as creating a specific file).  
    2. Run the migration command (for example, via `python manage.py migrate`).  
    3. Observe that during the migration process the payload is unpickled and its effects are observed (e.g. the file is created, or a logged message confirms code execution).  
    4. Verify that once proper mitigations are applied (for example, by replacing `pickle.loads` with a safe deserialization function or by pre‑validating data) the migration does not allow dangerous payloads to be executed.

---

- **Vulnerability Name:** Insecure File Upload Path Handling in ConstanceForm

  - **Description:**  
    In the live settings update form (implemented in `constance/forms.py`), the `save()` method processes file uploads. It iterates over uploaded files in `self.files` and saves each file using:  
    ```python
    default_storage.save(join(settings.FILE_ROOT, file.name), file)
    ```  
    Here, the filename (`file.name`) comes directly from user input and is concatenated with a configurable file root. If `file.name` contains directory traversal sequences such as `"../"`, the computed target path may point outside the intended upload directory.
    **Step‑by-step triggering:**  
    1. An attacker (who must have access to the live settings form—that is, an authenticated user with the `constance.change_config` permission) submits the form with an uploaded file whose filename includes directory traversal characters (for example, `"../../malicious.py"`).  
    2. The code builds the save path by using Python’s `os.path.join(settings.FILE_ROOT, file.name)`.  
    3. If no explicit sanitization is performed, the resulting path may resolve to a location outside the designated directory, thereby writing the file to an unintended location.
  
  - **Impact:**  
    This vulnerability can lead to arbitrary file writes. An attacker could potentially save or overwrite files in sensitive directories. In some configurations (for instance, if files are saved into a web‑accessible directory), this might lead to remote code execution.
  
  - **Vulnerability Rank:**  
    High
  
  - **Currently Implemented Mitigations:**  
    While the code uses Django’s `default_storage.save()` method—which in many installations will run some name‐cleaning—the Constance code itself does not explicitly sanitize or validate the uploaded filename before passing it to the storage backend.
  
  - **Missing Mitigations:**  
    • Explicitly sanitize the uploaded filename to remove or neutralize directory traversal characters (for example, by applying Django’s `get_valid_filename()` or `os.path.basename()`).  
    • Validate that the resulting file path remains within an expected safe directory (i.e. ensure that the path is a child of `settings.FILE_ROOT`).  
    • Consider rejecting file names that contain suspicious characters.
  
  - **Preconditions:**  
    • The attacker must have access to the live settings admin form (i.e. be a superuser or have been granted the `constance.change_config` permission).  
    • The application must be configured so that file uploads are enabled and the uploader does not enforce additional sanitization beyond what Django’s default storage provides.
  
  - **Source Code Analysis:**  
    • In `constance/forms.py`, within the `ConstanceForm.save()` method, the code processes uploaded file fields by looping over `self.files`.  
    • For each file field, it retrieves the file object and uses `file.name` in the following manner:  
      ```python
      self.cleaned_data[file_field] = default_storage.save(join(settings.FILE_ROOT, file.name), file)
      ```  
    • No explicit sanitization (such as stripping directory separators or validating the final path) is applied to `file.name` before it is concatenated with the file root.  
    • This could allow an attacker to manipulate the path if they can control the name of the file being uploaded.
  
  - **Security Test Case:**  
    1. As an attacker (or a tester simulating an attacker in a controlled environment), log in with an account that has permission to change configuration values (for example, a superuser account).  
    2. Navigate to the live settings update page where file uploads are accepted.  
    3. Using a tool such as Burp Suite or by modifying the multipart POST request manually, submit the form with a file upload where the file’s name is set to include directory traversal characters (for example, `"../../evil_script.py"`).  
    4. After submission, inspect the storage location on the server to verify whether the file was saved outside of the intended `FILE_ROOT`.  
    5. A successful test is indicated if the file is found at an unintended location; a secure implementation will either sanitize the filename (e.g. reducing it to a safe basename) or reject the input outright.