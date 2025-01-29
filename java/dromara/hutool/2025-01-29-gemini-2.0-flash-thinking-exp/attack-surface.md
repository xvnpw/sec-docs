# Attack Surface Analysis for dromara/hutool

## Attack Surface: [Path Traversal](./attack_surfaces/path_traversal.md)

*   **Description:** Attackers can access files and directories outside of the intended application directory by manipulating file paths provided as input.
*   **Hutool Contribution:** Hutool's `FileUtil` and `IoUtil` provide methods for file operations. Using these with unsanitized user input for file paths directly contributes to this attack surface.
*   **Example:**
    *   Application uses `FileUtil.readString(FileUtil.file(userInput))` with `userInput` from a user request.
    *   Attacker provides `userInput` as `../../../../etc/passwd`.
    *   `FileUtil.readString` attempts to read `/etc/passwd`, exposing sensitive information.
*   **Impact:** Unauthorized file access, information disclosure.
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   **Input Validation:** Validate user-provided file paths against an allowlist of permitted characters and directory structures.
    *   **Path Sanitization:** Sanitize user input to remove or encode path traversal sequences like `..`.
    *   **`FileUtil.isSubpath`:** Use `FileUtil.isSubpath` to ensure paths are within expected base directories.

## Attack Surface: [Zip Slip](./attack_surfaces/zip_slip.md)

*   **Description:** A path traversal vulnerability in zip archive extraction. Malicious zip files contain entries with filenames like `../../../malicious.file`, leading to file extraction outside the intended directory.
*   **Hutool Contribution:** `ZipUtil.unzip` can be vulnerable if filenames within the zip archive are not validated before extraction, directly enabling Zip Slip attacks.
*   **Example:**
    *   Application uses `ZipUtil.unzip(uploadedZipFile, targetDirectory)`.
    *   Attacker uploads a zip with an entry named `../../../malicious.jsp`.
    *   `ZipUtil.unzip` extracts `malicious.jsp` outside `targetDirectory`, potentially to a web-accessible location.
*   **Impact:** Arbitrary file write, potentially leading to Remote Code Execution (RCE).
*   **Risk Severity:** Critical
*   **Mitigation Strategies:**
    *   **Filename Validation:** Validate filenames within zip archives before extraction, rejecting entries with path traversal sequences (`../`).
    *   **Secure Zip Libraries:** Consider using zip libraries with built-in Zip Slip protection.
    *   **Extraction Path Control:** Strictly control and isolate the target extraction directory.

## Attack Surface: [Insecure Deserialization](./attack_surfaces/insecure_deserialization.md)

*   **Description:** Deserializing data from untrusted sources without validation can allow attackers to inject malicious serialized objects, leading to arbitrary code execution upon deserialization.
*   **Hutool Contribution:** `SerializeUtil.deserialize` provides object deserialization. Using it on untrusted data directly introduces insecure deserialization risks.
*   **Example:**
    *   Application receives serialized data from a user and uses `SerializeUtil.deserialize(userInputData)`.
    *   Attacker crafts malicious serialized data containing exploit code.
    *   `SerializeUtil.deserialize` executes the malicious code during deserialization.
*   **Impact:** Remote Code Execution (RCE), full system compromise.
*   **Risk Severity:** Critical
*   **Mitigation Strategies:**
    *   **Avoid Deserialization of Untrusted Data:**  Minimize or eliminate deserializing data from untrusted sources.
    *   **Input Validation & Integrity Checks:** If necessary, validate input data and use integrity checks (signatures) to ensure data authenticity.
    *   **Whitelisting Deserialization:** If using Java serialization, use whitelists to restrict deserializable classes.
    *   **Secure Serialization Formats:** Prefer safer formats like JSON or Protocol Buffers over Java serialization for untrusted data.

## Attack Surface: [Server-Side Request Forgery (SSRF)](./attack_surfaces/server-side_request_forgery__ssrf_.md)

*   **Description:** Attackers can induce the server to make requests to unintended locations (internal resources, external services) by manipulating URLs used in server-side HTTP requests.
*   **Hutool Contribution:** `HttpUtil` and `HttpRequest` simplify HTTP requests. Using user-controlled input to construct URLs for these requests without validation directly enables SSRF.
*   **Example:**
    *   Application uses `HttpUtil.createGet(userInputUrl).executeStr()` with `userInputUrl` from user input.
    *   Attacker provides `userInputUrl` as `http://localhost/admin/deleteUser?user=attacker`.
    *   `HttpUtil.createGet` makes a request to the internal admin endpoint, potentially triggering unintended actions.
*   **Impact:** Access to internal resources, information disclosure, potential RCE via vulnerable internal services.
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   **URL Validation and Sanitization:** Validate and sanitize user-provided URLs against allowlists of protocols, domains, and ports.
    *   **URL Parsing and Filtering:** Parse URLs and filter out dangerous components or schemes.
    *   **Blocklist Internal Networks:** Block requests to internal network ranges unless explicitly required and secured.

## Attack Surface: [XML External Entity (XXE) Injection](./attack_surfaces/xml_external_entity__xxe__injection.md)

*   **Description:** Exploiting vulnerabilities in XML parsers to include malicious external entities in XML documents. This can lead to local file read, SSRF, or DoS.
*   **Hutool Contribution:** `XmlUtil.parseXml` can be vulnerable if parsing XML from untrusted sources without disabling external entity processing, directly enabling XXE attacks.
*   **Example:**
    *   Application uses `XmlUtil.parseXml(userInputXml)` to parse user-provided XML.
    *   Attacker provides XML with a malicious external entity to read `/etc/passwd`.
    *   `XmlUtil.parseXml` (with default settings) processes the entity, exposing `/etc/passwd` content.
*   **Impact:** Information disclosure (local file read), Server-Side Request Forgery (SSRF).
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   **Disable External Entity Processing:** Configure XML parsers to disable external entity processing (using `XMLConstants.FEATURE_SECURE_PROCESSING` or parser-specific settings).
    *   **Input Validation:** Validate and sanitize XML input to detect and reject malicious structures.
    *   **Secure XML Parsers:** Use up-to-date and secure XML parsing libraries with secure configurations.

## Attack Surface: [Script Injection/Remote Code Execution (via Scripting)](./attack_surfaces/script_injectionremote_code_execution__via_scripting_.md)

*   **Description:** Injecting malicious scripts into the application, which are then executed by the application's scripting engine, leading to arbitrary code execution.
*   **Hutool Contribution:** `ScriptUtil.eval` allows executing scripts. Using user-controlled input to construct or execute scripts via `ScriptUtil.eval` without sanitization directly enables script injection and RCE.
*   **Example:**
    *   Application uses `ScriptUtil.eval("javascript", userInputScript)`.
    *   Attacker provides `userInputScript` containing malicious JavaScript to execute system commands.
    *   `ScriptUtil.eval` executes the malicious script, leading to command execution on the server.
*   **Impact:** Remote Code Execution (RCE), full system compromise.
*   **Risk Severity:** Critical
*   **Mitigation Strategies:**
    *   **Avoid Script Execution of User Input:**  Avoid executing scripts based on user input whenever possible.
    *   **Sandboxing:** If scripting is necessary, use sandboxed scripting environments with restricted access.
    *   **Input Validation & Sanitization:** If user input is used in scripts, rigorously validate and sanitize it to remove malicious code. Use allowlists for permitted script commands.

