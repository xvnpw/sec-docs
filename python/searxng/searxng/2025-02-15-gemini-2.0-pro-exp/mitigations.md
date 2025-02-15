# Mitigation Strategies Analysis for searxng/searxng

## Mitigation Strategy: [Engine Selection and Configuration](./mitigation_strategies/engine_selection_and_configuration.md)

**Description:**
1.  **Identify Trusted Engines:** Research and compile a list of search engines with good security and privacy practices.
2.  **`settings.yml` - `disabled` Flag:** Open `settings.yml`. In the `engines` section, set `disabled: true` for *untrusted* engines. Set `disabled: false` (or remove the line) for *trusted* engines.
3.  **`settings.yml` - `url` (HTTPS):** For each enabled engine, ensure the `url` setting uses `https://` if the engine supports it.
4.  **`settings.yml` - `safesearch`:** If supported by the engine, set `safesearch: 1` or `2` (check engine documentation) to filter inappropriate content.
5.  **Restart SearXNG:** Restart the SearXNG service.
6.  **Regular Review:** Periodically review and update the enabled engines list.

**Threats Mitigated:**
*   **Information Disclosure (High Severity):** Reduces leakage of queries to untrusted engines.
*   **Code Execution (Critical Severity):** Limits attack surface from malicious engine responses.
*   **Denial of Service (Medium Severity):** Reduces DoS risk from a single compromised engine.
*   **Manipulated Search Results (Medium Severity):** Lowers the chance of biased results.

**Impact:**
*   **Information Disclosure:** Significantly reduces risk.
*   **Code Execution:** Significantly reduces risk.
*   **Denial of Service:** Moderately reduces risk.
*   **Manipulated Search Results:** Significantly reduces risk.

**Currently Implemented:**
*   `settings.yml` allows enabling/disabling engines via `disabled`.
*   HTTPS is encouraged and often the default.
*   `safesearch` is available for many engines.

**Missing Implementation:**
*   No formal "whitelisting" beyond the `disabled` flag.
*   No automated engine vulnerability checks.

## Mitigation Strategy: [Per-Engine Rate Limiting and Timeouts](./mitigation_strategies/per-engine_rate_limiting_and_timeouts.md)

**Description:**
1.  **Research Engine Limits:** Find the rate limits imposed by each enabled search engine (API documentation).
2.  **`settings.yml` - `limit`:** In the `engines` section of `settings.yml`, set the `limit` value (requests per time unit) for each engine.  Set this *below* the engine's actual limit.
3.  **`settings.yml` - `timeout`:** Set the `timeout` value (in seconds) for each engine.  This is how long SearXNG will wait for a response.
4.  **Restart SearXNG:** Restart the service.

**Threats Mitigated:**
*   **Denial of Service (Medium Severity):** Helps prevent overwhelming backend engines.
*   **Engine Blocking (Medium Severity):** Reduces the risk of your instance being blocked by engines.

**Impact:**
*   **Denial of Service:** Moderately reduces risk.
*   **Engine Blocking:** Significantly reduces risk.

**Currently Implemented:**
*   `settings.yml` supports `limit` and `timeout` settings per engine.

**Missing Implementation:**
*   No dynamic adjustment of rate limits based on engine responses.

## Mitigation Strategy: [Input Validation and Sanitization](./mitigation_strategies/input_validation_and_sanitization.md)

**Description:**
1.  **Code Review:** Examine the SearXNG codebase (particularly `searx/webutils.py` and engine-specific files) for input handling.
2.  **Strengthen Validation:**  Improve existing validation to be more restrictive:
    *   **Length Limits:** Enforce stricter query length limits.
    *   **Character Restrictions:**  Allow only a very limited set of characters (alphanumeric, spaces, minimal punctuation).  Disallow potentially dangerous characters.
    *   **Consider Whitelisting:**  Instead of blacklisting characters, consider a whitelist of *allowed* characters.
3.  **Enhance Sanitization:**  If certain characters can't be blocked, ensure they are properly escaped or encoded (e.g., HTML entities).
4.  **Output Encoding:**  Verify that *all* output to the user's browser is properly HTML-encoded to prevent XSS.
5.  **Testing:** Thoroughly test with various inputs, including malicious payloads.

**Threats Mitigated:**
*   **Code Execution (Critical Severity):** Prevents injection attacks against engines or SearXNG.
*   **Cross-Site Scripting (XSS) (High Severity):** Prevents injecting malicious JavaScript.

**Impact:**
*   **Code Execution:** Significantly reduces risk (with improvements).
*   **Cross-Site Scripting (XSS):** Significantly reduces risk.

**Currently Implemented:**
*   *Some* input validation and sanitization exists, mainly for XSS prevention.

**Missing Implementation:**
*   Input validation could be significantly more robust (stricter character restrictions, whitelisting).
*   No specific keyword blacklisting.

## Mitigation Strategy: [Plugin Management](./mitigation_strategies/plugin_management.md)

**Description:**
1.  **Source Verification:** Only use plugins from the official repository or trusted sources.
2.  **Code Review:** *Manually* review the source code of *every* plugin before enabling it. Look for vulnerabilities and suspicious code.
3.  **`settings.yml` - Enable/Disable:** In `settings.yml`, enable only the *necessary* plugins.  Disable any unused plugins.
4.  **Configuration Audit:** Review plugin configurations in `settings.yml` for security.
5.  **Keep Updated:** If updates are available *and you've reviewed the changes*, update plugins.

**Threats Mitigated:**
*   **Code Execution (Critical Severity):** Reduces risk from malicious plugins.
*   **Information Disclosure (High Severity):** Prevents plugins from leaking data.
*   **Denial of Service (Medium Severity):** Minimizes DoS risk from plugins.
*   **Manipulated Search Results (Medium Severity):** Lowers risk of altered results.

**Impact:**
*   **Code Execution:** Significantly reduces risk (with careful code review).
*   **Information Disclosure:** Significantly reduces risk.
*   **Denial of Service:** Moderately reduces risk.
*   **Manipulated Search Results:** Moderately reduces risk.

**Currently Implemented:**
*   Plugin system exists; plugins can be enabled/disabled in `settings.yml`.

**Missing Implementation:**
*   No automated plugin vetting or security checks.  *Manual code review is essential.*
*   No automated plugin updates.
*   No plugin isolation.

## Mitigation Strategy: [Logging Configuration](./mitigation_strategies/logging_configuration.md)

**Description:**
1.  **`settings.yml` - `log_level`:** Open `settings.yml`. Set `log_level` to `WARNING` or `ERROR` for production.  Avoid `DEBUG`.
2.  **Verify No Query Logging:** Double-check that there are *no* settings that would cause search queries to be logged.
3.  **Secure Log Storage (External):** *This is outside SearXNG, but crucial:* Ensure log files are stored securely with restricted access.
4.  **Log Rotation (External):** *Also external:* Implement log rotation and deletion (e.g., using `logrotate`).

**Threats Mitigated:**
*   **Information Disclosure (High Severity):** Reduces risk of data exposure through logs.

**Impact:**
*   **Information Disclosure:** Significantly reduces risk.

**Currently Implemented:**
*   `settings.yml` allows configuring the `log_level`.

**Missing Implementation:**
*   No built-in mechanism to *guarantee* queries aren't logged (relies on careful configuration).
*   No built-in log rotation (requires external tools).

## Mitigation Strategy: [Dependency Management](./mitigation_strategies/dependency_management.md)

**Description:**
1.  **`requirements.txt` - Pin Versions:**  In `requirements.txt`, specify *exact* versions for *all* dependencies (e.g., `requests==2.28.1`).  No ranges or wildcards.
2.  **Regular Updates:** Periodically:
    *   Check for updates: `pip list --outdated`.
    *   Review release notes for security fixes.
    *   Update versions in `requirements.txt`.
    *   Test thoroughly.
3. **Vulnerability Scanning (External):** Use tools like `pip-audit` to scan for vulnerabilities.

**Threats Mitigated:**
 *   **Code Execution (Critical Severity):** Reduces risk from vulnerable dependencies.
 *   **Information Disclosure (High Severity):** Prevents dependency vulnerabilities from leaking data.
 *   **Denial of Service (Medium Severity):** Minimizes DoS risk from dependencies.

**Impact:**
*   **Code Execution:** Significantly reduces risk.
*   **Information Disclosure:** Significantly reduces risk.
*   **Denial of Service:** Moderately reduces risk.

**Currently Implemented:**
*  SearXNG uses `requirements.txt`.

**Missing Implementation:**
*   Dependencies are *not* strictly pinned in the official `requirements.txt`.  **This is a major issue that needs to be addressed by anyone deploying SearXNG.**
*   No automated vulnerability scanning is integrated.

