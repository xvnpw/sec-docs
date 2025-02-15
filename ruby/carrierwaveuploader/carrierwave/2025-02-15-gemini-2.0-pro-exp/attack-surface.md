# Attack Surface Analysis for carrierwaveuploader/carrierwave

## Attack Surface: [1. Unrestricted File Upload](./attack_surfaces/1__unrestricted_file_upload.md)

*   **Description:** Attackers upload malicious files (e.g., web shells, executables) to gain control of the server.
*   **CarrierWave Contribution:** CarrierWave provides the file upload mechanism; without proper configuration, it accepts any file type.
*   **Example:** An attacker uploads a PHP web shell (`shell.php`) disguised as a JPG (`shell.php.jpg` or by manipulating the `Content-Type` header). The server executes the PHP code, granting the attacker control.
*   **Impact:** Remote Code Execution (RCE), complete server compromise, data theft, data destruction.
*   **Risk Severity:** Critical
*   **Mitigation Strategies:**
    *   **Strict `extension_allowlist`:** Define a very restrictive list of allowed file extensions (e.g., `['jpg', 'jpeg', 'png', 'gif']`). *Never* rely on blacklisting.
    *   **Content Type Validation (Secondary):** Use a gem like `Marcel` or `MimeMagic` to validate the *content* of the file, not just the extension or client-provided header.
    *   **Randomized Filenames:** Store files with randomly generated names (e.g., using `SecureRandom.uuid`).
    *   **No Default Uploaders:** Avoid using a default uploader without any configuration. Always explicitly configure each uploader.
    *   **Sanitize Filenames:** Ensure that filenames are properly sanitized.

## Attack Surface: [2. Directory Traversal](./attack_surfaces/2__directory_traversal.md)

*   **Description:** Attackers manipulate filenames to write files outside the intended upload directory, potentially overwriting system files.
*   **CarrierWave Contribution:** CarrierWave handles file storage; improper `store_dir` configuration can allow attackers to specify arbitrary paths.
*   **Example:** An attacker uploads a file named `../../../etc/passwd`. If `store_dir` is not properly secured, this could overwrite the system's password file.
*   **Impact:** System file corruption, privilege escalation, denial of service.
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   **Secure `store_dir`:** Configure `store_dir` to return a path *relative* to a safe, non-web-accessible root directory. *Never* allow user input to directly influence `store_dir`.
    *   **Filename Sanitization:** Ensure CarrierWave's filename sanitization is effective in removing directory traversal sequences (e.g., `../`).
    *   **OS Permissions:** Limit the web server's write permissions to only the designated upload directory.

## Attack Surface: [3. Image Processing Exploits (ImageTragick and similar)](./attack_surfaces/3__image_processing_exploits__imagetragick_and_similar_.md)

*   **Description:** Attackers exploit vulnerabilities in image processing libraries (e.g., ImageMagick) to achieve RCE.
*   **CarrierWave Contribution:** CarrierWave often integrates with image processing libraries (MiniMagick, RMagick) which are wrappers around ImageMagick.  This makes CarrierWave a *direct pathway* to these vulnerabilities if image processing is enabled.
*   **Example:** An attacker uploads a specially crafted image file that triggers a known ImageMagick vulnerability (like ImageTragick), leading to RCE.
*   **Impact:** Remote Code Execution (RCE), complete server compromise.
*   **Risk Severity:** Critical
*   **Mitigation Strategies:**
    *   **Update Dependencies:** *Crucially*, keep ImageMagick, MiniMagick, RMagick, and all related gems *up-to-date*.
    *   **`policy.xml` (ImageMagick):** Configure ImageMagick's `policy.xml` to disable vulnerable coders (e.g., `MVG`, `MSL`, `EPHEMERAL`).
    *   **Sandboxing:** Run image processing in a sandboxed environment (e.g., Docker).
    *   **Avoid `image/svg+xml`:** Be extremely cautious with SVG files.

## Attack Surface: [4. Server-Side Request Forgery (SSRF) via Remote URLs](./attack_surfaces/4__server-side_request_forgery__ssrf__via_remote_urls.md)

*   **Description:** Attackers provide URLs to internal services, exploiting CarrierWave's remote file download feature.
*   **CarrierWave Contribution:** CarrierWave's `remote_<attribute>_url` feature allows downloading files from user-provided URLs. This is a *direct* feature of CarrierWave.
*   **Example:** An attacker provides a URL like `http://localhost:22` (SSH) or `http://169.254.169.254/latest/meta-data/` (AWS metadata) to access internal services or sensitive data.
*   **Impact:** Exposure of internal services, data breaches, potential for further attacks.
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   **URL Allowlist:** *Strictly* limit the domains allowed for remote downloads.
    *   **IP Address Restrictions:** Restrict downloads to specific IP ranges, if possible.
    *   **Network Segmentation:** Limit the application server's access to internal resources.
    *   **Block Internal IPs:** Explicitly block URLs pointing to `localhost`, `127.0.0.1`, or internal IPs.
    *   **Set Timeout:** Implement short timeout for remote file downloads.

## Attack Surface: [5. Unvalidated Redirects and Forwards (Remote URLs)](./attack_surfaces/5__unvalidated_redirects_and_forwards__remote_urls_.md)

* **Description:** If the remote server responds with a redirect, CarrierWave might follow it. An attacker could use this to redirect the request to a malicious server.
* **CarrierWave Contribution:** CarrierWave's `remote_<attribute>_url` feature allows downloading files from user-provided URLs and follows redirects by default.
* **Example:** An attacker provides URL that redirects to malicious server that serves malicious file.
* **Impact:** Download of malicious file, potential RCE.
* **Risk Severity:** High
* **Mitigation Strategies:**
    *   **Limit Redirects:** Configure CarrierWave (or the underlying HTTP client) to limit the number of redirects it follows.
    *   **Validate Redirect URLs:** If you must follow redirects, validate the target URL against your allowlist *after* each redirect.

