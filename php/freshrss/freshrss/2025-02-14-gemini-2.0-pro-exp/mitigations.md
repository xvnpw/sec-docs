# Mitigation Strategies Analysis for freshrss/freshrss

## Mitigation Strategy: [Aggressive HTML Sanitization (within FreshRSS)](./mitigation_strategies/aggressive_html_sanitization__within_freshrss_.md)

*   **Description:**
    1.  **Locate HTMLPurifier Configuration:** Find the HTMLPurifier configuration file. This is typically within the `lib/htmlpurifier/` directory, possibly `HTMLPurifier.standalone.php` or a similar file, or within FreshRSS's own configuration files (e.g., `data/config.php`).
    2.  **Customize Configuration:**  Open the configuration file and *strictly* define allowed HTML elements, attributes, and URI schemes.
    3.  **Whitelist Approach:** Use a whitelist.  Explicitly list *only* essential tags (e.g., `p`, `a`, `img`, `strong`, `em`, `ul`, `ol`, `li`, `br`, `blockquote`).  *Disallow* potentially dangerous tags (e.g., `script`, `iframe`, `object`, `embed`, `form`, `input`, `style`, `link`).
    4.  **Restrict Attributes:** For allowed elements, whitelist only necessary attributes (e.g., `href`, `src`, `alt`, `title`).  *Never* allow event handlers (e.g., `onclick`, `onload`).
    5.  **Sanitize `href`:**  Ensure `href` attributes are validated to prevent `javascript:` URLs. Allow only `http:` and `https:`.
    6.  **Update HTMLPurifier:** Keep the HTMLPurifier library files updated to the latest version within the `lib/` directory.

*   **Threats Mitigated:**
    *   **Cross-Site Scripting (XSS) (High Severity):**  This is the primary defense against XSS via malicious feed content.
    *   **Content Spoofing (Medium Severity):**  Limits the ability to inject misleading HTML or styling.

*   **Impact:**
    *   **XSS:** Risk significantly reduced (from High to Low/Medium).
    *   **Content Spoofing:** Risk reduced (from Medium to Low/Medium).

*   **Currently Implemented:**
    *   FreshRSS *uses* HTMLPurifier, but the default configuration is likely *not* strict enough.

*   **Missing Implementation:**
    *   The default HTMLPurifier configuration needs *significant* tightening.  A thorough review and customization are essential.  Regular updates are also important.

## Mitigation Strategy: [Disable Unnecessary Features and Extensions (within FreshRSS)](./mitigation_strategies/disable_unnecessary_features_and_extensions__within_freshrss_.md)

*   **Description:**
    1.  **Identify Unused Features:** Determine which FreshRSS features you don't need (e.g., "reading view").
    2.  **Disable Features:** Disable them through FreshRSS's configuration options (often in `data/config.php` or the web interface).
    3.  **List Extensions:** Go to the "Extensions" section in the FreshRSS admin interface.
    4.  **Disable Unnecessary Extensions:** Disable any extensions you don't absolutely require.
    5.  **Remove Files (Optional):** For added security, delete the files of disabled extensions from the `extensions/` directory.

*   **Threats Mitigated:**
    *   **XSS (High Severity):** Reduces the attack surface.
    *   **CSRF (Medium Severity):** Reduces the attack surface.
    *   **SSRF (High Severity):** Reduces the attack surface.
    *   **Other Extension-Specific Vulnerabilities (Variable Severity):** Eliminates risks from disabled extensions.

*   **Impact:**
    *   **XSS:** Risk reduced.
    *   **CSRF:** Risk reduced.
    *   **SSRF:** Risk reduced.
    *   **Other Extension-Specific Vulnerabilities:** Risk eliminated for disabled extensions.

*   **Currently Implemented:**
    *   FreshRSS allows disabling features and extensions.

*   **Missing Implementation:**
    *   No specific missing implementation; this is a matter of user configuration.

## Mitigation Strategy: [URL Validation for SSRF (within FreshRSS Code)](./mitigation_strategies/url_validation_for_ssrf__within_freshrss_code_.md)

*   **Description:**
    1.  **Locate URL Fetching Code:** Find the code responsible for fetching external content (likely in `app/Models/`, `lib/`, or similar directories related to feed parsing).
    2.  **Implement Validation Function:** Create a PHP function (e.g., `isValidExternalUrl`) to validate URLs *before* fetching them.
    3.  **Strict Regular Expression:** Use a strict regular expression within the function to:
        *   Reject localhost (`127.0.0.1`, `localhost`).
        *   Reject private IP ranges (e.g., `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`).
        *   Reject unusual ports (unless specifically validated).
        *   Reject suspicious characters or encoding.
    4.  **Integrate with Fetching Logic:** Call this validation function *before* any `file_get_contents()`, `curl_exec()`, or similar function that fetches external content.  Do *not* fetch if validation fails.
    5. **Example PHP function:**
        ```php
        function isValidExternalUrl($url) {
            // Basic URL parsing
            $parsedUrl = parse_url($url);
            if (!$parsedUrl || !isset($parsedUrl['host'])) {
                return false;
            }

            $host = $parsedUrl['host'];

            // Reject localhost
            if ($host === 'localhost' || $host === '127.0.0.1') {
                return false;
            }

            // Reject private IP ranges
            if (filter_var($host, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
                if (preg_match('/^(10\.|172\.(1[6-9]|2[0-9]|3[0-1])\.|192\.168\.)/', $host)) {
                    return false;
                }
            }
            // Add additional checks for port, scheme, etc. as needed.
            return true;
        }
        ```

*   **Threats Mitigated:**
    *   **Server-Side Request Forgery (SSRF) (High Severity):** This is the primary target.

*   **Impact:**
    *   **SSRF:** Risk reduced (from High to Medium/Low).

*   **Currently Implemented:**
    *   FreshRSS *attempts* some basic SSRF protection, but it's likely not comprehensive.

*   **Missing Implementation:**
    *   A robust URL validation function, as described, needs to be implemented and integrated into the code. This is a *crucial* addition.

## Mitigation Strategy: [Two-Factor Authentication (2FA) (via FreshRSS Extension)](./mitigation_strategies/two-factor_authentication__2fa___via_freshrss_extension_.md)

*   **Description:**
    1.  **Install 2FA Extension:** Install a 2FA extension for FreshRSS (e.g., "Two-Factor TOTP Authentication") through the FreshRSS extensions interface.
    2.  **Enable 2FA:** Enable 2FA in the FreshRSS settings, either globally or for individual users.
    3.  **User Setup:** Each user sets up 2FA using an authenticator app (e.g., Google Authenticator, Authy).
    4.  **Enforce 2FA (Optional):** Consider making 2FA mandatory for all users, especially administrators.

*   **Threats Mitigated:**
    *   **Credential Stuffing (High Severity):** Makes credential-based attacks much harder.
    *   **Brute-Force Attacks (High Severity):** Renders brute-force attacks ineffective.
    *   **Phishing (High Severity):** Adds protection against phishing.

*   **Impact:**
    *   **Credential Stuffing:** Risk significantly reduced (from High to Low).
    *   **Brute-Force Attacks:** Risk almost eliminated (from High to Negligible).
    *   **Phishing:** Risk significantly reduced (from High to Medium/Low).

*   **Currently Implemented:**
    *   FreshRSS supports 2FA *via extensions*.

*   **Missing Implementation:**
    *   2FA is *not* enabled by default. It needs to be installed and configured.

## Mitigation Strategy: [Secure Configuration (within FreshRSS `data/config.php`)](./mitigation_strategies/secure_configuration__within_freshrss__dataconfig_php__.md)

*   **Description:**
    1.  **Locate `data/config.php`:**  Find the main FreshRSS configuration file.
    2.  **Review Settings:** Carefully review *all* settings within this file.
    3.  **Environment Variables:**  Where possible, move sensitive information (database credentials, API keys) to *environment variables* instead of storing them directly in `config.php`.  This requires modifying the code that reads these values to use `getenv()` or similar functions.
    4. **Check API keys:** Ensure that API keys are strong and not default.

*   **Threats Mitigated:**
    *   **Information Disclosure (High Severity):** Reduces the risk of exposing sensitive data if the configuration file is compromised.
    *   **Unauthorized Access (High Severity):** Protects API keys.

*   **Impact:**
    *   **Information Disclosure:** Risk reduced.
    *   **Unauthorized Access:** Risk reduced.

*   **Currently Implemented:**
    *   FreshRSS uses `data/config.php` for configuration.  The use of environment variables is *inconsistent*.

*   **Missing Implementation:**
    *   Consistent use of environment variables for *all* sensitive data is a key area for improvement.

## Mitigation Strategy: [Limit number of feeds](./mitigation_strategies/limit_number_of_feeds.md)

* **Description:**
    1. Go to FreshRSS administration interface.
    2. Go to "Subscription Management" section.
    3. Review list of feeds.
    4. Remove unnecessary feeds.

* **Threats Mitigated:**
    * **Denial of Service (DoS) (Medium Severity):** Reduces load on the server.

* **Impact:**
    * **DoS:** Risk reduced (from Medium to Low).

* **Currently Implemented:**
    * FreshRSS allows to manage feeds.

* **Missing Implementation:**
    * No specific missing implementation. This is a matter of user configuration.

## Mitigation Strategy: [Increase refresh interval](./mitigation_strategies/increase_refresh_interval.md)

* **Description:**
    1. Go to FreshRSS administration interface.
    2. Go to "Configuration" section.
    3. Go to "Refreshing" tab.
    4. Increase "Average refresh period" value.

* **Threats Mitigated:**
    * **Denial of Service (DoS) (Medium Severity):** Reduces load on the server.

* **Impact:**
    * **DoS:** Risk reduced (from Medium to Low).

* **Currently Implemented:**
    * FreshRSS allows to configure refresh interval.

* **Missing Implementation:**
    * No specific missing implementation. This is a matter of user configuration.

