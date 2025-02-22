* **Vulnerability Name:** Directory Traversal via Malicious Filename in Image Upload
  - **Description:**
    In the images plugin, the file upload path is determined by the function `upload_path(instance, filename)` in `/code/src/wiki/plugins/images/models.py`. This function takes the provided filename and concatenates it with a designated upload directory (derived from the setting `IMAGE_PATH`). However, no sanitization is performed on the incoming filename. An attacker may therefore supply a filename containing directory traversal sequences (such as `"../../evil.jpg"`). When the file is saved, the computed upload path (using `os.path.join(upload_path, filename)`) may resolve to a location outside the intended directory.
    *Step‑by‑step Trigger:*
      1. An attacker crafts an image file with a filename that includes directory traversal sequences (for example, `"../../evil.jpg"`).
      2. The attacker uploads this file using the publicly accessible image upload interface (provided by the images plugin).
      3. The `upload_path` function replaces any `%aid` token with the target article’s ID and (if enabled) appends a random obscurification hash but then directly appends the unsanitized filename.
      4. As a result, the final file path may escape the designated upload directory and be placed in an unintended location, possibly overwriting existing files or permitting arbitrary file placement.
  - **Impact:**
    An attacker who successfully uploads a file using a malicious filename can overwrite important files or cause files to be stored in locations that may later be executed by the web server. This can lead to the compromise of file integrity and even remote code execution if the uploaded file is placed in a web‑accessible directory.
  - **Vulnerability Rank:** High
  - **Currently Implemented Mitigations:**
    The image file is handled by Django’s built-in file upload mechanism and stored using the path defined in the configuration (via `settings.IMAGE_PATH`). However, the filename itself is not validated or sanitized before being concatenated into the storage path.
  - **Missing Mitigations:**
    - Sanitize the user‑supplied filename to remove or neutralize directory traversal characters (for example by applying `os.path.basename()` or using Django’s `get_valid_filename()`).
    - Enforce a strict whitelist for acceptable filename characters and patterns.
    - Normalize the final file path and verify it resides within the intended upload directory before writing the file.
  - **Preconditions:**
    - The image upload endpoint (provided by the images plugin) must be publicly accessible.
    - The deployment must be using the file storage configuration specified by `settings.IMAGE_PATH` (with or without obscurification) and must permit the filesystem to respond to relative path injections.
  - **Source Code Analysis:**
    In `/code/src/wiki/plugins/images/models.py` the function is defined as follows:
    ```python
    def upload_path(instance, filename):
        upload_path = settings.IMAGE_PATH
        upload_path = upload_path.replace("%aid", str(instance.plugin.image.article.id))
        if settings.IMAGE_PATH_OBSCURIFY:
            import uuid
            upload_path = os.path.join(upload_path, uuid.uuid4().hex)
        return os.path.join(upload_path, filename)
    ```
    - The function performs a simple string replacement on `%aid` and (optionally) appends a random hash if obscurification is enabled.
    - It then uses `os.path.join` to concatenate the result with the supplied `filename` without any sanitization.
    - An attacker-controlled filename such as `"../../evil.jpg"` will be joined directly to the computed upload path, possibly causing the final path to resolve outside the intended directory.
  - **Security Test Case:**
    1. Deploy the application (or use a test instance) with the images plugin active.
    2. Access the image upload function through the public interface.
    3. Prepare a valid image file (for example, a JPEG) and rename it to include directory traversal sequences (e.g., `"../../evil.jpg"`).
    4. Upload the file via the provided form—noting that the backend uses the `upload_path` function as defined above.
    5. Check the media (or file storage) directory to determine whether the file has been stored outside of the intended folder (e.g. by confirming if a file named “evil.jpg” appears in a parent directory).
    6. Optionally, attempt to trigger overwriting of critical files if the deployment permits such actions, confirming that the file placement is not properly constrained.