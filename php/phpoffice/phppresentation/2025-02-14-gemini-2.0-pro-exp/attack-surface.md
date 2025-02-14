# Attack Surface Analysis for phpoffice/phppresentation

## Attack Surface: [XML External Entity (XXE) Injection](./attack_surfaces/xml_external_entity__xxe__injection.md)

*   **Description:** Exploitation of insecure XML parsing to access local files, perform SSRF, or cause DoS.
*   **phpoffice/phppresentation Contribution:** The library parses XML as part of the OOXML (PPTX) format. If the underlying XML parser is misconfigured, it becomes vulnerable. This is a *direct* involvement because the library's core functionality relies on XML parsing.
*   **Example:** An attacker uploads a PPTX file containing an XML entity that references a sensitive local file (e.g., `/etc/passwd`) or an internal service endpoint.
*   **Impact:**
    *   Disclosure of sensitive local files.
    *   Server-Side Request Forgery (SSRF) to internal or external systems.
    *   Denial of Service (DoS).
*   **Risk Severity:** Critical
*   **Mitigation Strategies:**
    *   **Developer:**
        *   **Disable External Entity Resolution:** Use `libxml_disable_entity_loader(true);` in PHP *before* any XML parsing operations related to the library. This is the *primary* defense and is absolutely essential.
        *   **Validate XML Schema (if feasible):** If a strict schema is available, validate against it. This is a secondary, more complex defense.

## Attack Surface: [XML Bomb (Billion Laughs Attack)](./attack_surfaces/xml_bomb__billion_laughs_attack_.md)

*   **Description:**  Denial of Service attack using exponentially expanding XML entities.
*   **phpoffice/phppresentation Contribution:** The library parses XML, making it susceptible to resource exhaustion if entity expansion isn't limited.  This is *direct* involvement as the library's core functionality includes XML parsing.
*   **Example:** An attacker uploads a PPTX file with deeply nested XML entities that consume all available memory.
*   **Impact:** Denial of Service (DoS) due to resource exhaustion (CPU, memory).
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   **Developer:**
        *   **Limit XML Entity Expansion:** Check if the underlying XML parser has built-in limits (and verify they are enabled). If not, implement application-level checks to limit recursion depth and overall entity expansion.
        *   **Limit File Size:** Enforce a reasonable maximum file size for uploaded PPTX files. This is a general good practice and helps mitigate this specific attack.
        *   **Resource Monitoring:** Monitor server resources (CPU, memory) during PPTX processing.

## Attack Surface: [Image/Media Parsing Vulnerabilities](./attack_surfaces/imagemedia_parsing_vulnerabilities.md)

*   **Description:** Exploitation of vulnerabilities in image/media parsing libraries used by `phpoffice/phppresentation`.
*   **phpoffice/phppresentation Contribution:** The library *directly* interacts with and relies on external image/media processing libraries (e.g., GD, ImageMagick) when handling embedded content within PPTX files.  This is a direct involvement because the library's functionality includes processing these embedded resources.
*   **Example:** An attacker embeds a maliciously crafted image within a PPTX file, designed to trigger a buffer overflow in the image parsing library (e.g., a known vulnerability in an older version of GD).
*   **Impact:**
    *   Remote Code Execution (RCE) (if the underlying library vulnerability allows it).
    *   Denial of Service (DoS).
    *   Information Disclosure.
*   **Risk Severity:** High (potentially Critical if RCE is possible)
*   **Mitigation Strategies:**
    *   **Developer:**
        *   **Keep Libraries Updated:** Ensure GD, ImageMagick, and any other image/media processing libraries are up-to-date with the latest security patches. This is *crucial*. Use `composer update` regularly and monitor for security advisories related to these libraries.
        *   **Input Validation (Image):** Validate image dimensions, file sizes, and file types *before* passing them to the processing libraries. This can help prevent some exploits.
        *   **Sandboxing (Ideal):** Process images in a sandboxed environment (e.g., a container) to limit the impact of any vulnerabilities. This is the most robust mitigation.

## Attack Surface: [Zip Slip Vulnerability](./attack_surfaces/zip_slip_vulnerability.md)

*   **Description:** Exploitation of insecure file extraction to write files outside the intended directory.
*   **phpoffice/phppresentation Contribution:** If the application extracts files from a ZIP archive (which PPTX files are) and uses those files with `phpoffice/phppresentation`, a vulnerability could exist. This is direct involvement, because phppresentation is working with extracted files.
*   **Example:** An attacker uploads a crafted PPTX file with a filename containing ".." sequences, causing files to be extracted to an unintended location on the server.
*   **Impact:**
    *   Overwriting critical system files.
    *   Remote Code Execution (RCE).
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   **Developer:**
        *   **Validate Filenames:** Before extracting files, thoroughly validate filenames to ensure they don't contain directory traversal characters ("../", "..\", etc.).
        *   **Use Secure Extraction Functions:** Use secure file extraction functions that are designed to prevent Zip Slip vulnerabilities. Avoid custom extraction logic.
        *   **Least Privilege:** Run the extraction process with the least necessary privileges.

