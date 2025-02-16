# Attack Surface Analysis for thoughtbot/paperclip

## Attack Surface: [Spoofed Content-Type (File Type Masquerading)](./attack_surfaces/spoofed_content-type__file_type_masquerading_.md)

*   **Description:** An attacker uploads a file with a malicious extension (e.g., `.php`, `.exe`, `.sh`) but disguises it by setting a harmless `Content-Type` header (e.g., `image/jpeg`).
*   **Paperclip Contribution:** Paperclip, by default, uses the client-provided `Content-Type` for initial validation. While it *can* be configured to use more robust methods (magic number checks), the default behavior and misconfigurations can make this attack possible.  This is a *direct* Paperclip concern because it's the component handling the initial file type determination.
*   **Example:** An attacker uploads a file named `malicious.php` but sets the `Content-Type` to `image/jpeg`. If Paperclip only checks the `Content-Type`, the file is accepted as an image. If the server later executes this file, the PHP code will run.
*   **Impact:** Remote Code Execution (RCE), complete system compromise.
*   **Risk Severity:** Critical
*   **Mitigation Strategies:**
    *   **Do not rely solely on `Content-Type`:** Configure Paperclip to use file signature (magic number) validation *in addition to* content type checks.
    *   **Whitelist and Blacklist:** Use a strict whitelist of allowed file extensions *and* a blacklist of known dangerous extensions.
    *   **Validate after processing:** If the file is processed (e.g., resized), re-validate the file type *after* processing.
    *   **Use `validates_attachment_file_type`:** Ensure this validation is *not* disabled (i.e., `do_not_validate_attachment_file_type` is *not* set to `true`).
    *   **Content-Security-Policy (CSP):** Use CSP headers to restrict the types of content that can be executed.

## Attack Surface: [Command Injection (via Post-Processors)](./attack_surfaces/command_injection__via_post-processors_.md)

*   **Description:** An attacker exploits vulnerabilities in external libraries used by Paperclip's processors (e.g., ImageMagick) to inject malicious commands.
*   **Paperclip Contribution:** Paperclip *directly* enables this by allowing the definition of custom "processors" that execute external commands on uploaded files.  The vulnerability arises from how Paperclip interfaces with these external tools and how user input might be unsafely passed to them.
*   **Example:** An application uses ImageMagick for resizing and allows users to specify dimensions. An attacker provides `100x100; rm -rf /`. If this is passed directly to ImageMagick, the command could be executed.
*   **Impact:** Remote Code Execution (RCE), data deletion, system compromise.
*   **Risk Severity:** Critical
*   **Mitigation Strategies:**
    *   **Strict Input Sanitization:** Thoroughly sanitize *all* user input used in processor commands. Use whitelisting and escaping. *Never* directly embed user input.
    *   **Parameterization:** Use parameterized interfaces to external libraries instead of constructing command strings.
    *   **Least Privilege:** Run processing commands with the lowest possible privileges.
    *   **Alternative Libraries:** Consider more secure alternatives to ImageMagick (e.g., libvips).
    *   **Sandboxing:** Run processing commands in a sandboxed environment.

## Attack Surface: [Directory Traversal](./attack_surfaces/directory_traversal.md)

*   **Description:** An attacker manipulates the file path used for storage to write files outside the intended directory.
*   **Paperclip Contribution:** Paperclip *directly* contributes to this through its use of interpolations to construct file paths.  If these interpolations are based on unsanitized user input, directory traversal is possible. The application's *use* of Paperclip's features is the key factor.
*   **Example:** If the filename is directly used in the storage path, and an attacker uploads `../../etc/passwd`, the file might overwrite the system's `/etc/passwd`.
*   **Impact:** File overwrite, data corruption, potential system compromise.
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   **Sanitize Filenames:** Thoroughly sanitize filenames and any user input used in paths. Remove or escape `..`, `/`, and `\`.
    *   **Use Unique Identifiers:** Generate unique identifiers (e.g., UUIDs) for filenames and use those in the storage path.
    *   **Validate Paths:** Before writing, validate that the final path is within the intended directory.
    *   **Least Privilege:** Run the application with minimum file system permissions.

## Attack Surface: [Denial of Service (DoS) - Image Processing](./attack_surfaces/denial_of_service__dos__-_image_processing.md)

*   **Description:** An attacker uploads a crafted image ("image bomb") to consume excessive resources during processing.
*   **Paperclip Contribution:** Paperclip's *direct* use of image processing libraries (like ImageMagick), especially when configured to perform transformations, makes this attack possible. The vulnerability lies in the interaction between Paperclip and the potentially vulnerable image processing library.
*   **Example:** An attacker uploads a "pixel flood" image that expands to a massive size in memory during processing, crashing the server.
*   **Impact:** Service unavailability.
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   **Resource Limits:** Configure resource limits (memory, CPU time) for image processing.
    *   **Alternative Libraries:** Consider more secure and resource-efficient image processing libraries (e.g., libvips).
    *   **Input Validation:** Validate image dimensions and properties *before* processing.
    *   **Timeout Processing:** Set timeouts for image processing operations.

## Attack Surface: [XXE (XML External Entity) Attack](./attack_surfaces/xxe__xml_external_entity__attack.md)

*   **Description:** If Paperclip processes XML files (e.g., SVG), an attacker can exploit XXE vulnerabilities.
*   **Paperclip Contribution:** Paperclip's *direct* handling of XML-based file types (if configured to do so) opens the possibility of XXE attacks if the underlying XML parser is not secure. The vulnerability stems from Paperclip's decision to process a potentially dangerous file type.
*   **Example:** An attacker uploads an SVG file with an XXE payload to read a sensitive system file (e.g., `/etc/passwd`).
*   **Impact:** Information disclosure, Server-Side Request Forgery (SSRF), Denial of Service (DoS).
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   **Disable External Entities:** Configure the XML parser to disable processing of external entities and DTDs.
    *   **Use a Secure XML Parser:** Ensure a secure and up-to-date XML parser is used.
    *   **Input Validation:** Validate the content of XML files.

