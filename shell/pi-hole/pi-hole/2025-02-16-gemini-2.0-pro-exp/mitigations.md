# Mitigation Strategies Analysis for pi-hole/pi-hole

## Mitigation Strategy: [Enable DNSSEC Validation](./mitigation_strategies/enable_dnssec_validation.md)

*   **Description:**
    1.  **Access Pi-hole Web Interface:** Open a web browser and navigate to the Pi-hole's web interface (usually `http://<pi-hole-ip>/admin`).
    2.  **Login:** Enter your Pi-hole administrative password.
    3.  **Navigate to Settings:** Click on "Settings" in the left-hand sidebar.
    4.  **Select DNS Tab:** Click on the "DNS" tab at the top of the settings page.
    5.  **Enable DNSSEC:** Locate the "Use DNSSEC" checkbox.  Ensure it is checked.
    6.  **Verify Upstream DNS Servers:**  Confirm that the upstream DNS servers you have selected *also* support DNSSEC.  If they don't, DNSSEC validation will not be effective. You may need to research your chosen providers.
    7.  **Save Changes:** Click the "Save" button at the bottom of the page.
    8.  **Test:** Use online tools like `https://dnssec.vs.uni-due.de/` to test.

*   **Threats Mitigated:**
    *   **DNS Spoofing/Cache Poisoning:** (Severity: **High**)
    *   **Man-in-the-Middle (MitM) Attacks (related to DNS):** (Severity: **High**)

*   **Impact:**
    *   **DNS Spoofing/Cache Poisoning:** Risk significantly reduced.
    *   **MitM Attacks (DNS-related):** Additional layer of security.

*   **Currently Implemented:** Yes, fully implemented within Pi-hole.

*   **Missing Implementation:**
    *   **More Prominent DNSSEC Status:** Displaying status more prominently.
    *   **Automated Upstream DNS Server Verification:** Checking if upstream servers support DNSSEC.
    *   **DNSSEC Troubleshooting Tools:** Built-in tools for diagnosis.

## Mitigation Strategy: [Use Trusted Upstream DNS Servers with DoH/DoT](./mitigation_strategies/use_trusted_upstream_dns_servers_with_dohdot.md)

*   **Description:**
    1.  **Access Pi-hole Web Interface:** Open the web interface.
    2.  **Login:** Enter your password.
    3.  **Navigate to Settings:** Click "Settings".
    4.  **Select DNS Tab:** Click the "DNS" tab.
    5.  **Choose Upstream DNS Servers:** Select from pre-configured servers or enter custom addresses. Prioritize providers with DoH/DoT support (Cloudflare, Google, Quad9).
    6.  **Enable DoH/DoT:** Select the appropriate option (dropdown or checkbox). You may need the DoH/DoT endpoint URL (from the provider's documentation).
    7.  **Save Changes:** Click "Save".
    8.  **Test:** Verify DNS resolution is working.

*   **Threats Mitigated:**
    *   **DNS Eavesdropping:** (Severity: **High**)
    *   **DNS Tampering/Hijacking (MitM):** (Severity: **High**)
    *   **Reliance on Untrusted Local Resolvers:** (Severity: **Medium**)

*   **Impact:**
    *   **DNS Eavesdropping:** Risk eliminated (to the DoH/DoT provider).
    *   **DNS Tampering/Hijacking:** Risk significantly reduced.
    *   **Reliance on Untrusted Local Resolvers:** Risk eliminated.

*   **Currently Implemented:** Yes, fully implemented within Pi-hole.

*   **Missing Implementation:**
    *   **Automatic DoH/DoT Fallback:** Secure handling of DoH/DoT failures.
    *   **Simplified DoH/DoT Configuration:** Easier setup for popular providers.
    *   **DoH/DoT Connection Status:** Clearer status display.

## Mitigation Strategy: [Use Well-Maintained and Reputable Blocklists](./mitigation_strategies/use_well-maintained_and_reputable_blocklists.md)

*   **Description:**
    1.  **Access Pi-hole Web Interface:** Open the web interface.
    2.  **Login:** Enter your password.
    3.  **Navigate to Group Management -> Adlists:** Click "Group Management" then "Adlists".
    4.  **Review Existing Lists:** Examine current adlists.
    5.  **Add Reputable Lists:** Consider adding lists from reputable sources (Firebog, StevenBlack's Unified Hosts).
    6.  **Avoid Obscure Lists:** Do *not* add lists from unknown sources.
    7.  **Update Gravity:** After changes, click "Update Gravity" (or run `pihole -g`).
    8.  **Test:** Monitor the query log for false positives.

*   **Threats Mitigated:**
    *   **False Positives:** (Severity: **Medium**)
    *   **Outdated Blocklists:** (Severity: **Medium**)
    *   **Malicious Blocklists:** (Severity: **Low**, but potentially **High** impact)

*   **Impact:**
    *   **False Positives:** Risk significantly reduced.
    *   **Outdated Blocklists:** Risk reduced.
    *   **Malicious Blocklists:** Risk minimized.

*   **Currently Implemented:** Yes, fully implemented within Pi-hole.

*   **Missing Implementation:**
    *   **Automated Blocklist Reputation Scoring:** Rating system for blocklists.
    *   **Blocklist Categorization:** Categorizing lists (advertising, tracking, etc.).
    *   **Built-in Blocklist Recommendations:** More specific recommendations.

## Mitigation Strategy: [Regularly Review and Whitelist as Needed](./mitigation_strategies/regularly_review_and_whitelist_as_needed.md)

*   **Description:**
    1.  **Access Pi-hole Web Interface:** Open the web interface.
    2.  **Login:** Enter your password.
    3.  **Review Query Log:** Click "Query Log".
    4.  **Identify Blocked Domains:** Look for blocked domains.
    5.  **Investigate:** Determine if the blocked domain is legitimate.
    6.  **Whitelist Domains:** Click "Whitelist" next to the domain, or go to "Group Management" -> "Domains" and add it manually.
    7.  **Update Gravity:**  Good practice after whitelisting (`pihole -g` or web interface button).
    8.  **Test:** Verify access to the previously blocked domain.

*   **Threats Mitigated:**
    *   **False Positives:** (Severity: **Medium**)

*   **Impact:**
    *   **False Positives:** Risk significantly reduced.

*   **Currently Implemented:** Yes, fully implemented within Pi-hole.

*   **Missing Implementation:**
    *   **Bulk Whitelisting:** Adding multiple domains at once.
    *   **Whitelist Import/Export:** For backups and sharing.
    *   **Temporary Whitelisting:** Whitelisting for a limited time.

## Mitigation Strategy: [Strong Password for Web Interface](./mitigation_strategies/strong_password_for_web_interface.md)

*   **Description:**
    1.  **Initial Setup:** During installation, set a strong password. *Do not skip this*.
    2.  **Changing the Password:** Use `pihole -a -p` from the command line.
    3.  **Password Characteristics:** Long (12+ characters), complex (uppercase, lowercase, numbers, symbols), unique, and not easily guessable.
    4. **Store Securely:** Use password manager.

*   **Threats Mitigated:**
    *   **Unauthorized Access (Brute-Force):** (Severity: **High**)
    *   **Unauthorized Access (Dictionary Attack):** (Severity: **High**)
    *   **Credential Stuffing:** (Severity: **Medium**)

*   **Impact:**
    *   **Unauthorized Access:** Risk significantly reduced.

*   **Currently Implemented:** Yes, password setting is part of Pi-hole's setup and management.

*   **Missing Implementation:**
    *   **Password Strength Meter:** Visual indicator of strength.
    *   **Two-Factor Authentication (2FA):** Highly requested feature.
    *   **Account Lockout:** After failed login attempts.

## Mitigation Strategy: [Rate Limiting (FTL Settings)](./mitigation_strategies/rate_limiting__ftl_settings_.md)

*   **Description:**
    1.  **Access Pi-hole Configuration File:**  Using SSH or a terminal, access the Pi-hole server.
    2.  **Edit `pihole-FTL.conf`:** Open the file `/etc/pihole/pihole-FTL.conf` with a text editor (e.g., `sudo nano /etc/pihole/pihole-FTL.conf`).
    3.  **Modify `FTLCONF_RATE_LIMIT`:**  Find the `FTLCONF_RATE_LIMIT` setting.  This setting controls the rate limiting.  The format is `queries/seconds`.  For example, `FTLCONF_RATE_LIMIT=1000/60` would limit to 1000 queries per 60 seconds (per client).
    4.  **Adjust Values:**  Adjust the values based on your network needs and the Pi-hole's hardware capabilities.  Start with a reasonable value and monitor performance.  Too low a value can cause legitimate queries to be dropped.
    5.  **Save and Restart FTL:** Save the changes to the file and restart the FTL service: `sudo systemctl restart pihole-FTL.service`.
    6. **Test:** Monitor Pi-Hole performance.

*   **Threats Mitigated:**
    *   **Denial of Service (DoS) against Pi-hole:** (Severity: **Medium**)

*   **Impact:**
    *   **DoS:** Risk significantly reduced. Prevents a single client or flood of requests from overwhelming Pi-hole.

*   **Currently Implemented:** Yes, rate limiting is a built-in feature of Pi-hole's FTL DNS resolver.

*   **Missing Implementation:**
    *   **Web Interface Configuration:**  Currently, rate limiting can only be configured via the command line.  Adding this to the web interface would improve usability.
    *   **More Granular Control:**  Potentially, more granular control over rate limiting (e.g., different limits for different client groups).
    *   **Dynamic Rate Limiting:**  Adjusting rate limits automatically based on current load.

## Mitigation Strategy: [Regularly Update Pi-hole](./mitigation_strategies/regularly_update_pi-hole.md)

*   **Description:**
    1. **Update via Command Line:** The recommended method is to use the command `pihole -up` from the Pi-hole's terminal (via SSH or direct access).
    2. **Update via Web Interface:** Alternatively, log into the Pi-hole web interface, and if an update is available, there will be a notification and an option to update.
    3. **Follow Prompts:** The update process will download and install the latest versions of Pi-hole's components (core, FTL, web interface).
    4. **Automatic Updates (Caution):** Pi-hole *can* be configured for automatic updates, but this should be done with caution. Ensure you have a backup and monitoring in place in case an update causes issues.

*   **Threats Mitigated:**
    *   **Vulnerabilities in DNS Resolver (FTL):** (Severity: **High**)
    *   **Vulnerabilities in Web Interface:** (Severity: **High**)
    *   **Vulnerabilities in Other Components:** (Severity: **High**)
    *   **Exploitation of Known Bugs:** (Severity: **Medium**)

*   **Impact:**
    *   **All Vulnerabilities:** Risk significantly reduced by applying updates promptly. Updates patch security flaws.

*   **Currently Implemented:** Yes, Pi-hole provides both command-line and web interface update mechanisms.

*   **Missing Implementation:**
    *   **More Detailed Update Information:** Providing more detailed information about what changes are included in each update (e.g., a link to a changelog).
    *   **Rollback Capability:** A simple way to roll back to a previous version if an update causes problems.
    *   **Staged Rollouts:** An option to participate in staged rollouts of updates (receiving updates slightly later than the bleeding edge, but potentially more stable).

