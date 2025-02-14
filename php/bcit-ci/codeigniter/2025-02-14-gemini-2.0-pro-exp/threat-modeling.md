# Threat Model Analysis for bcit-ci/codeigniter

## Threat: [Outdated Framework Exploitation](./threats/outdated_framework_exploitation.md)

*   **Description:** An attacker identifies the application is running an outdated version of BCIT CodeIgniter. They search for publicly disclosed vulnerabilities (CVEs) or known exploits targeting that specific version or its bundled libraries. They then craft and send malicious requests designed to trigger these vulnerabilities.
*   **Impact:** Remote Code Execution (RCE), allowing the attacker to execute arbitrary code on the server; Data breaches, exposing sensitive information; Denial of Service (DoS); Complete system compromise.
*   **CodeIgniter Component Affected:** The entire framework and its bundled libraries (potentially including core system files, database drivers, encryption libraries, etc.).
*   **Risk Severity:** Critical.
*   **Mitigation Strategies:**
    *   **Primary:** Migrate to a supported framework (e.g., Laravel, Symfony, or a maintained fork of CodeIgniter 4).
    *   **Secondary (if migration is impossible immediately):**
        *   Manually audit the CodeIgniter codebase and all dependencies for known vulnerabilities. Apply patches manually if available (extremely risky).
        *   Implement a Web Application Firewall (WAF) with rules specifically targeting known CodeIgniter exploits (a compensating control).
        *   Use a vulnerability scanner that specifically checks for CodeIgniter vulnerabilities.

## Threat: [Default Encryption Key Usage](./threats/default_encryption_key_usage.md)

*   **Description:** The application uses the default `encryption_key` in `config.php`. An attacker, knowing this common oversight, can decrypt any data encrypted by the application (e.g., session data, cookies, stored encrypted data). They might use this to forge session tokens, impersonate users, or access sensitive information.
*   **Impact:** Session hijacking, data breaches, unauthorized access to sensitive data, privilege escalation.
*   **CodeIgniter Component Affected:** `Encryption` library, `Session` library (if using encrypted sessions), any custom code using the `Encryption` library.
*   **Risk Severity:** Critical.
*   **Mitigation Strategies:**
    *   Generate a strong, random encryption key (at least 32 bytes) and set it in `config.php`.
    *   Store the encryption key securely, *outside* of the web root and codebase (e.g., using environment variables).
    *   Rotate encryption keys periodically.

## Threat: [Insecure Session Management (File-Based)](./threats/insecure_session_management__file-based_.md)

*   **Description:** The application uses the default `files` session driver (`$config['sess_driver'] = 'files';`) with default file permissions. An attacker with local access to the server (e.g., through another compromised application or a shared hosting environment) can read the session files, potentially obtaining session IDs of other users. They can then hijack those sessions.
*   **Impact:** Session hijacking, unauthorized access to user accounts, privilege escalation.
*   **CodeIgniter Component Affected:** `Session` library, specifically the `files` driver.
*   **Risk Severity:** High (especially in shared hosting environments).
*   **Mitigation Strategies:**
    *   Use a more secure session driver: `database`, `redis`, or `memcached`.
    *   If using the `files` driver, ensure the session save path (`$config['sess_save_path']`) is outside the web root and has restricted permissions (only readable/writable by the web server user).
    *   Configure session timeouts appropriately.
    *   Use HTTPS to prevent session ID sniffing over the network.

## Threat: [SQL Injection via Database Library Misuse](./threats/sql_injection_via_database_library_misuse.md)

*   **Description:**  A developer fails to use CodeIgniter's query bindings (prepared statements) *consistently* when interacting with the database.  Even though the `DB` library *supports* them, direct string concatenation or improper escaping is used in some queries. An attacker crafts malicious input that modifies the SQL query.
*   **Impact:** Data breaches, data modification, data deletion, potentially RCE (depending on the database and privileges).
*   **CodeIgniter Component Affected:** `Database` library (`DB` class).
*   **Risk Severity:** High.
*   **Mitigation Strategies:**
    *   *Always* use query bindings (prepared statements) for *all* database queries, without exception.  Never directly concatenate user input into SQL queries.
    *   Use CodeIgniter's Active Record class consistently and correctly.
    *   Regularly review code for any instances of direct SQL query construction.

## Threat: [Arbitrary File Upload via File Upload Library Misuse](./threats/arbitrary_file_upload_via_file_upload_library_misuse.md)

*   **Description:** The application uses CodeIgniter's `Upload` library but doesn't properly validate uploaded files. An attacker uploads a malicious file (e.g., a PHP script disguised as an image) that bypasses the weak or missing validation. The file is then saved to a location accessible by the web server.
*   **Impact:** Remote Code Execution (RCE), complete system compromise.
*   **CodeIgniter Component Affected:** `Upload` library.
*   **Risk Severity:** Critical.
*   **Mitigation Strategies:**
    *   Strictly validate file types using MIME type detection (not just file extensions). Use a whitelist of allowed MIME types.
    *   Limit file sizes to a reasonable maximum.
    *   Rename uploaded files.
    *   Store uploaded files *outside* the web root, in a directory with restricted permissions.
    *   Do *not* rely on client-side file type validation.

## Threat: [Over-Reliance on Global XSS Filtering](./threats/over-reliance_on_global_xss_filtering.md)

*   **Description:** The application relies *solely* on CodeIgniter's `$config['global_xss_filtering'] = TRUE;` setting for XSS protection. While this provides some basic filtering, it's not foolproof and can be bypassed.
*   **Impact:** Cross-Site Scripting (XSS), allowing the attacker to execute malicious scripts in the context of other users' browsers.
*   **CodeIgniter Component Affected:** Input library (and potentially any component that handles user input).
*   **Risk Severity:** High.
*   **Mitigation Strategies:**
    *   Do *not* rely solely on global XSS filtering.
    *   Use context-appropriate output encoding (e.g., HTML encoding, JavaScript encoding) when displaying user-supplied data.
    *   Use a Content Security Policy (CSP).
    *   Sanitize input using a dedicated HTML sanitization library if you need to allow some HTML tags.

