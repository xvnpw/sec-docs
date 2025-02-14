# Mitigation Strategies Analysis for bcit-ci/codeigniter

## Mitigation Strategy: [Enforce Robust CSRF Protection (CodeIgniter's Security Class)](./mitigation_strategies/enforce_robust_csrf_protection__codeigniter's_security_class_.md)

**Description:**
1.  **Global Enablement:** In `application/config/config.php`, ensure `$config['csrf_protection'] = TRUE;`. This leverages CodeIgniter's built-in CSRF protection.
2.  **Token Inclusion (Automatic with `form_open()`):** Use CodeIgniter's `form_open()` helper function to generate HTML forms. This *automatically* includes a hidden CSRF token field.  Do *not* create forms manually without including the token.
3.  **AJAX Token Handling (Using CodeIgniter Functions):** For AJAX requests:
    *   Retrieve the token name and value using CodeIgniter's functions: `$csrf_name = $this->security->get_csrf_token_name();` and `$csrf_hash = $this->security->get_csrf_hash();`.
    *   Include the token in *every* AJAX request (POST, PUT, DELETE), preferably in the request headers (e.g., `X-CSRF-TOKEN`).
4.  **Selective Exclusion (Using CodeIgniter's Configuration):** If specific routes *must* be excluded, use `$config['csrf_exclude_uris']` in `application/config/config.php`. Provide *precise* URI patterns.  Example: `$config['csrf_exclude_uris'] = array('api/v1/webhook');`.
5.  **Token Regeneration (Using CodeIgniter's Session Library):** After significant actions (login, password change), regenerate the token. If using CodeIgniter's session library, use `$this->session->sess_regenerate();`.  If not using sessions, call `$this->security->get_csrf_hash();` again to get a new hash, and ensure this new hash is sent to the client.
6. **Double Submit Cookie (If no sessions):** If you are not using CodeIgniter sessions, implement the Double Submit Cookie pattern. Generate a cryptographically secure random value. Set this value in both a cookie (HttpOnly, Secure) and a hidden field in the form/request body. Server-side, verify that both values match.

**Threats Mitigated:**
*   **Cross-Site Request Forgery (CSRF):** (Severity: High)
*   **Session Riding:** (Severity: High)

**Impact:**
*   **CSRF:** Risk significantly reduced (90-95%) with correct usage of CodeIgniter's CSRF protection features.
*   **Session Riding:** Risk reduced to a similar extent as CSRF.

**Currently Implemented:**
*   `config.php`: `$config['csrf_protection'] = TRUE;`
*   `Views`: Forms use `form_open()`.
*   `JavaScript (main.js)`: AJAX requests include `X-CSRF-TOKEN`.

**Missing Implementation:**
*   `API Controllers`: Broad CSRF exclusion (`api/*`). Needs refinement.
*   `User Controller`: Token regeneration missing after login/logout/password changes.
* Double Submit Cookie is not implemented.

## Mitigation Strategy: [Secure Session Management (CodeIgniter's Session Library)](./mitigation_strategies/secure_session_management__codeigniter's_session_library_.md)

**Description:**
1.  **Database Driver:** In `application/config/config.php`, set `$config['sess_driver'] = 'database';` (or 'redis', 'memcached').  *Avoid* the `files` driver in production.
2.  **Table Creation (for Database Driver):** Ensure the session table (default: `ci_sessions`) exists and matches the CodeIgniter documentation's schema.
3.  **Configuration (Using CodeIgniter's Settings):** In `application/config/config.php`:
    *   `$config['sess_cookie_name'] = 'unique_session_name';`
    *   `$config['sess_expiration'] = 7200;`
    *   `$config['sess_save_path'] = 'ci_sessions';` (table name for database driver)
    *   `$config['sess_match_ip'] = FALSE;` (Initially FALSE; consider alternatives to IP matching)
    *   `$config['sess_time_to_update'] = 300;`
    *   `$config['sess_regenerate_destroy'] = TRUE;`
    *   `$config['cookie_httponly'] = TRUE;`
    *   `$config['cookie_secure'] = TRUE;` (Essential for production)
    *   `$config['cookie_samesite'] = 'Lax';` (or 'Strict')
4.  **Session Regeneration (Using CodeIgniter's Function):** In your authentication logic (e.g., `User` controller), call `$this->session->sess_regenerate();` after login, logout, and privilege changes.
5.  **Data Storage:** Store only a user identifier in the session. Retrieve sensitive data from the database using this identifier.

**Threats Mitigated:**
*   **Session Fixation:** (Severity: High)
*   **Session Hijacking:** (Severity: High)
*   **Session Prediction:** (Severity: High)
*   **Data Leakage:** (Severity: High)

**Impact:**
*   **Session Fixation, Hijacking, Prediction:** Risk significantly reduced (80-90%) with correct CodeIgniter session configuration.
*   **Data Leakage:** Risk minimized by not storing sensitive data in the session.

**Currently Implemented:**
*   `config.php`: Most session settings are correctly configured.
*   `Database`: `ci_sessions` table exists.

**Missing Implementation:**
*   `User Controller`: Session ID regeneration not consistent after all privilege changes.
*   `config.php`: `$config['sess_match_ip'] = TRUE;` - Needs review and potential change.

## Mitigation Strategy: [Secure Database Interactions (CodeIgniter's Active Record/Query Bindings)](./mitigation_strategies/secure_database_interactions__codeigniter's_active_recordquery_bindings_.md)

**Description:**
1.  **Prioritize Active Record:** Use CodeIgniter's Active Record class for *all* database interactions whenever possible.  Example: `$this->db->select('username, email')->from('users')->where('id', $user_id)->get();`.
2.  **Query Bindings (If Raw SQL is Necessary):** If you *must* use raw SQL, use CodeIgniter's query bindings: `$sql = "SELECT * FROM users WHERE username = ?"; $this->db->query($sql, array($username));`.  *Never* concatenate user input directly into SQL strings.
3.  **Database Configuration:** In `application/config/database.php`, ensure you are using a supported database driver (e.g., `mysqli`, `pdo`) and that it's configured to use prepared statements (usually the default).

**Threats Mitigated:**
*   **SQL Injection:** (Severity: Critical)

**Impact:**
*   **SQL Injection:** Risk drastically reduced (95-99%) with consistent use of Active Record or query bindings.

**Currently Implemented:**
*   `Controllers/Models`: Majority use Active Record.
*   `database.php`: `mysqli` driver with prepared statements.

**Missing Implementation:**
*   `Legacy Controller`: Contains raw SQL queries without proper binding. Needs refactoring.

## Mitigation Strategy: [Secure File Upload Handling (CodeIgniter's File Uploading Class)](./mitigation_strategies/secure_file_upload_handling__codeigniter's_file_uploading_class_.md)

**Description:**
1.  **Configuration (Within Your Controller):**
    *   `$config['upload_path'] = './uploads/';` (**Crucially, this must be *outside* the web root.** Use an absolute path like `/var/www/uploads/`).
    *   `$config['allowed_types'] = 'gif|jpg|png';` (Strict whitelist of extensions).
    *   `$config['max_size'] = '2048';` (Maximum file size in KB).
    *   `$config['encrypt_name'] = TRUE;` (Rename files to random, encrypted names).
2.  **Load Library:** `$this->load->library('upload', $config);`
3.  **Perform Upload:** `$this->upload->do_upload('userfile');`
4.  **Error Handling:** Check for errors using `$this->upload->display_errors();`.
5.  **File Serving (Separate Controller - Using CodeIgniter's Output Class):** Create a controller to serve files:
    *   Sanitize and validate the requested file name.
    *   Verify user authentication and authorization.
    *   Read the file from the *non-web-accessible* upload directory.
    *   Use CodeIgniter's Output class to set headers and output the file content: `$this->output->set_content_type()->set_output(file_get_contents($file_path));`.
6. **Image Manipulation (CodeIgniter's Image Library):** If handling images, use `$this->load->library('image_lib')` to process images *after* upload and *before* storing.

**Threats Mitigated:**
*   **Arbitrary File Upload:** (Severity: Critical)
*   **Directory Traversal:** (Severity: High)
*   **Denial of Service (DoS):** (Severity: Medium)
*   **Image-Based Vulnerabilities:** (Severity: Medium)

**Impact:**
*   **Arbitrary File Upload:** Risk significantly reduced (90-95%) with correct use of CodeIgniter's File Uploading Class and secure configuration.
*   **Directory Traversal:** Risk minimized by serving files through a controller.
*   **DoS:** Risk reduced by limiting file size.
*   **Image-Based Vulnerabilities:** Risk reduced by image processing.

**Currently Implemented:**
*   `Upload Controller`: Uses File Uploading Class.
*   `config`: `allowed_types`, `max_size`, `encrypt_name` configured.

**Missing Implementation:**
*   `Upload Path`: Files stored *within* web root. *Critical* issue.
*   `File Serving Controller`: Not implemented. Files accessed directly. *Critical* issue.
*   `Image Manipulation`: Not used.

## Mitigation Strategy: [Output Encoding and XSS Filtering (CodeIgniter's Security Helper and Output Class)](./mitigation_strategies/output_encoding_and_xss_filtering__codeigniter's_security_helper_and_output_class_.md)

**Description:**
1.  **Output Encoding (Primary - Using PHP Functions):** *Always* use `htmlspecialchars()` or `htmlentities()` when displaying user data in HTML. Use context-specific encoding (e.g., `json_encode()` for JavaScript).
2.  **`xss_clean()` (Secondary - CodeIgniter's Security Helper):** Use `$this->security->xss_clean($data);` as an *additional* layer of defense, *before* storing data in the database (if storing potentially HTML-containing data). Do *not* rely on it as the sole XSS protection.

**Threats Mitigated:**
*   **Cross-Site Scripting (XSS):** (Severity: High)

**Impact:**
*   **XSS:** Risk significantly reduced (90-95%) with consistent output encoding. `xss_clean()` provides an additional, limited layer.

**Currently Implemented:**
*   `Views`: Some views use `htmlspecialchars()`, but not consistently.
*   `Controllers`: `xss_clean()` used in some controllers, but not consistently.

**Missing Implementation:**
*   `Views`: Comprehensive review needed for consistent output encoding.
*   `Controllers`: Consistent use of `xss_clean()` as a secondary measure.

## Mitigation Strategy: [Prevent Directory Traversal (CodeIgniter's Security Helper)](./mitigation_strategies/prevent_directory_traversal__codeigniter's_security_helper_.md)

**Description:**
1.  **Avoid User Input in Paths:** If possible, avoid using user input directly in file paths.
2.  **Sanitization (Using CodeIgniter's Function):** If user input *must* be used, use `$this->security->sanitize_filename($user_input);` to remove dangerous characters.
3.  **Whitelist Validation:** If you have a limited set of allowed files/directories, validate against a whitelist.

**Threats Mitigated:**
*   **Directory Traversal:** (Severity: High)

**Impact:**
*   **Directory Traversal:** Risk significantly reduced (85-95%) with sanitization and whitelist validation.

**Currently Implemented:**
*   `File Download Controller`: `sanitize_filename()` is used.

**Missing Implementation:**
*   `Image Gallery Controller`: User input used in image paths *without* sanitization. *Critical* vulnerability.

## Mitigation Strategy: [Avoid Code Injection (Secure File Inclusion with CodeIgniter's View Loading)](./mitigation_strategies/avoid_code_injection__secure_file_inclusion_with_codeigniter's_view_loading_.md)

**Description:**
1.  **Avoid `eval()`:** Do *not* use `eval()` with untrusted input.
2.  **Secure File Inclusion (Using CodeIgniter's View Loading):** Do *not* include files based directly on user input. Use a whitelist and CodeIgniter's view loading mechanism:
    ```php
    $allowed_pages = array('home', 'about', 'contact');
    $page = $this->input->get('page'); // Use CodeIgniter's Input class
    if (in_array($page, $allowed_pages)) {
        $this->load->view($page); // Use CodeIgniter's view loader
    } else {
        $this->load->view('404');
    }
    ```

**Threats Mitigated:**
*   **Code Injection:** (Severity: Critical)

**Impact:**
*   **Code Injection:** Risk almost entirely eliminated by avoiding `eval()` and using secure file inclusion.

**Currently Implemented:**
*   `Application`: No instances of `eval()`.

**Missing Implementation:**
*   `Plugin System`: Includes files based on user input *without* validation. *Critical* vulnerability. Needs redesign using a whitelist and CodeIgniter's loading mechanisms.

