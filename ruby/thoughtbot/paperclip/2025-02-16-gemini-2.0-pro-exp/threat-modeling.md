# Threat Model Analysis for thoughtbot/paperclip

## Threat: [Threat 1: Malicious File Content (Disguised as Allowed Type)](./threats/threat_1_malicious_file_content__disguised_as_allowed_type_.md)

*   **Description:** An attacker crafts a file with a harmless extension (e.g., `.jpg`, `.png`, `.pdf`) but containing malicious code (e.g., a PHP script, shell script, or executable). The attacker aims to bypass Paperclip's validation, leading to server-side code execution or client-side attacks (like XSS) if the file is served to a browser. The attacker might embed shellcode within image data or rename a script.
    *   **Impact:** Remote Code Execution (RCE) on the server. Cross-Site Scripting (XSS). Data breaches, system compromise.
    *   **Affected Paperclip Component:** `Paperclip::Validators::ContentTypeValidator`, `Paperclip::Attachment#post_process`, and the storage mechanism (how Paperclip *validates* and *stores* the file).
    *   **Risk Severity:** Critical
    *   **Mitigation Strategies:**
        *   **Strict MIME Type Validation:** Use `Paperclip::Validators::ContentTypeValidator` with a *whitelist* of allowed MIME types (e.g., `['image/jpeg', 'image/png', 'application/pdf']`). *Never* use a blacklist.
        *   **Content Inspection:** Use a library like `mimemagic` or the `file` command (carefully sanitized) to inspect file *contents*, not just the extension or MIME type reported by the browser. Integrate this into a custom Paperclip validator.
        *   **Storage Outside Web Root:** Store files outside the web-accessible directory to prevent direct execution.
        *   **Serve via Controller:** Serve files through a controller, setting the correct `Content-Type` header based on *validated* MIME type.

## Threat: [Threat 2: ImageMagick Vulnerabilities (ImageTragick and related)](./threats/threat_2_imagemagick_vulnerabilities__imagetragick_and_related_.md)

*   **Description:** An attacker uploads a crafted image to exploit known vulnerabilities in ImageMagick (or other image processing libraries used by Paperclip). The attacker researches ImageMagick CVEs and creates an image to trigger a vulnerability during Paperclip's processing (e.g., resizing).
    *   **Impact:** Remote Code Execution (RCE) on the server. Denial of Service (DoS). Potential information disclosure.
    *   **Affected Paperclip Component:** `Paperclip::Attachment#post_process` (specifically, the interaction with ImageMagick or similar libraries).
    *   **Risk Severity:** Critical
    *   **Mitigation Strategies:**
        *   **Keep ImageMagick Updated:** *Crucially*, update ImageMagick (and other processing libraries) to the latest patched versions. Monitor security advisories.
        *   **ImageMagick Policy File:** Use a restrictive `policy.xml` to disable vulnerable coders and features (e.g., `MVG`, `MSL`, `EPHEMERAL`, `HTTPS` if not needed).
        *   **Alternative Libraries:** Consider using less vulnerable image processing libraries (e.g., MiniMagick with VIPS, or a cloud-based service).
        *   **Input Sanitization:** Sanitize any user-provided data passed to ImageMagick.
        *   **Sandboxing:** Run image processing in a sandboxed environment (e.g., Docker container) with limited privileges.

## Threat: [Threat 3: "Zip Bomb" or Archive Attacks](./threats/threat_3_zip_bomb_or_archive_attacks.md)

*   **Description:** If archive uploads are allowed, an attacker uploads a "zip bomb" – a highly compressed archive that expands to a huge size, causing a denial of service.
    *   **Impact:** Denial of service due to excessive disk space and memory consumption during decompression. Server crashes.
    *   **Affected Paperclip Component:** `Paperclip::Attachment#post_process` (if processing archive contents), `Paperclip::Validators::ContentTypeValidator` (if allowing archive types).
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   **Disable Archive Support:** If archive processing is *not* needed, *disable* it in `Paperclip::Validators::ContentTypeValidator`. This is the best solution.
        *   **Strict Size Limits (Archive and Decompressed):** If archive processing *is* needed, enforce *strict* limits on:
            *   The maximum size of the uploaded archive.
            *   The maximum size of the *decompressed* files (requires custom validation).
        *   **Secure Decompression Library:** Use a decompression library resistant to zip bomb attacks. Research its security.
        *   **Sandboxing:** Decompress archives in a sandboxed environment with limited resources.
        *   **Resource Monitoring:** Monitor resource usage during decompression; terminate if limits are exceeded.

## Threat: [Threat 4: Filename Manipulation (Path Traversal)](./threats/threat_4_filename_manipulation__path_traversal_.md)

* **Description:** An attacker attempts to upload a file with a manipulated filename containing path traversal characters (e.g., `../../`) to write the file to an arbitrary location on the server's filesystem.
    * **Impact:** Overwriting system files, leading to denial of service or RCE. Accessing or modifying sensitive data.
    * **Affected Paperclip Component:** `Paperclip::Attachment#path`, `Paperclip::Storage::Filesystem` (if using local filesystem storage). The vulnerability is in how Paperclip constructs the final file path.
    * **Risk Severity:** High (if using local filesystem storage)
    * **Mitigation Strategies:**
        * **Verify Paperclip's Sanitization:** Although Paperclip *should* sanitize filenames, explicitly verify this through testing and code review.
        * **Restricted Upload Directory:** Configure Paperclip to store files in a dedicated directory with *limited* permissions.
        * **No User Input in Paths:** *Never* directly use user-provided input when constructing the file path. Use a generated identifier or hash.
        * **Filesystem Permissions:** Ensure the application user has the *minimum* necessary permissions.

