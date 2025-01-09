# Threat Model Analysis for phpoffice/phpexcel

## Threat: [Formula Injection](./threats/formula_injection.md)

*   **Description:** An attacker crafts a spreadsheet file containing malicious formulas. When PHPExcel processes this file, particularly if user-uploaded, these formulas are evaluated, potentially executing arbitrary PHP code on the server. This could involve using functions like `SYSTEM`, `EXEC`, or custom functions if the application allows them.
*   **Impact:**  Remote code execution on the server, leading to complete compromise of the application and potentially the underlying server. Attackers could steal sensitive data, install malware, or pivot to other systems.
*   **Affected Component:**  `PHPExcel_Calculation` module, specifically the formula parsing and evaluation engine.
*   **Risk Severity:** Critical
*   **Mitigation Strategies:**
    *   Disable Formula Calculation: If formula evaluation is not required, disable it within PHPExcel's settings.
    *   Sanitize Input Data:  Before loading data into PHPExcel, sanitize any user-provided data that might end up in formulas.
    *   Use a Read-Only Mode: If possible, process files in a read-only mode that prevents formula evaluation.
    *   Implement Strict Input Validation:  Validate uploaded spreadsheet files to ensure they conform to expected structures and do not contain suspicious formulas.
    *   Run PHPExcel in a Sandboxed Environment:  Isolate the PHP process running PHPExcel to limit the damage in case of successful exploitation.

## Threat: [XML External Entity (XXE) Injection](./threats/xml_external_entity__xxe__injection.md)

*   **Description:** An attacker crafts a malicious spreadsheet file (e.g., .xlsx, which is XML-based) containing external entity declarations. When PHPExcel parses this XML, it might attempt to resolve these external entities, potentially leading to the disclosure of local files on the server or denial-of-service attacks.
*   **Impact:**  Disclosure of sensitive files on the server, denial-of-service by overloading the server with requests to resolve external entities, or potentially server-side request forgery (SSRF).
*   **Affected Component:**  `PHPExcel_Reader_Excel2007` and potentially other readers that handle XML-based formats, specifically the underlying XML parsing library used by PHPExcel.
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   Disable External Entity Resolution in XML Parser: Configure the underlying XML parser used by PHPExcel to disallow external entity loading. This might involve setting specific options in the XMLReader or SimpleXML extensions.
    *   Sanitize Input Files:  Inspect uploaded files for suspicious XML declarations before processing them with PHPExcel.
    *   Use a Non-Vulnerable XML Parser (If Possible): Explore if PHPExcel allows configuration to use a more secure XML parsing library.
    *   Run PHPExcel with Limited File System Permissions: Restrict the file system access of the PHP process running PHPExcel.

## Threat: [Zip Slip Vulnerability](./threats/zip_slip_vulnerability.md)

*   **Description:**  Spreadsheet formats like .xlsx are essentially ZIP archives. If PHPExcel extracts files from these archives without proper path sanitization, an attacker could craft a malicious archive containing files with pathnames like `../../../../evil.php`. When extracted, these files could overwrite critical system files.
*   **Impact:**  Arbitrary file write on the server, potentially leading to remote code execution or other system compromises.
*   **Affected Component:**  `PHPExcel_Reader_Excel2007` and potentially other readers that handle ZIP-based formats, specifically the ZIP extraction functionality.
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   Sanitize Extraction Paths:  Ensure that PHPExcel or the application code sanitizes the extracted file paths to prevent writing outside the intended directory.
    *   Extract to a Temporary Directory: Extract the contents of the ZIP archive to a temporary directory with restricted permissions and then process the files from there.
    *   Verify Extracted File Paths:  After extraction, verify that the extracted files are in the expected locations before further processing.

## Threat: [Exploiting Vulnerabilities in Specific File Format Parsers](./threats/exploiting_vulnerabilities_in_specific_file_format_parsers.md)

*   **Description:** PHPExcel supports various spreadsheet formats (.xls, .ods, .csv, etc.). Vulnerabilities might exist in the specific parsers for these formats. An attacker could craft a malicious file in a specific format to exploit a parsing flaw, potentially leading to remote code execution or other malicious activities.
*   **Impact:**  Remote code execution, information disclosure, or denial-of-service depending on the specific vulnerability.
*   **Affected Component:**  `PHPExcel_Reader_Excel5`, `PHPExcel_Reader_OOCalc`, `PHPExcel_Reader_CSV`, and other reader classes specific to different file formats.
*   **Risk Severity:** Varies (High to Medium depending on the vulnerability)
*   **Mitigation Strategies:**
    *   Keep PHPExcel Updated: Regularly update PHPExcel to the latest version to patch known vulnerabilities in the file format parsers.
    *   Limit Supported File Formats: Only enable support for the file formats that are strictly necessary for the application.
    *   Input Validation:  Validate the file format and structure before processing it with the corresponding PHPExcel reader.

