# Attack Surface Analysis for sj26/mailcatcher

## Attack Surface: [1. Unintended Public Exposure](./attack_surfaces/1__unintended_public_exposure.md)

*   **Description:** MailCatcher's web interface (port 1080) or SMTP port (1025) are accessible from the public internet or a broader network than intended.
*   **MailCatcher Contribution:** MailCatcher's default configuration listens on all interfaces, making it vulnerable to accidental exposure if firewall rules or network configurations are not properly set.
*   **Example:** A developer deploys MailCatcher to a cloud server without configuring the cloud provider's security groups to restrict access. An attacker scans for open ports and finds MailCatcher running on port 1080.
*   **Impact:** Attackers can view all captured emails, potentially containing sensitive information (password resets, API keys, internal communications). They might also attempt to use the SMTP port for reconnaissance.
*   **Risk Severity:** **Critical**
*   **Mitigation Strategies:**
    *   **Network Segmentation:** Use firewall rules (iptables, cloud security groups) to restrict access to MailCatcher's ports to only the local machine or a trusted development network.
    *   **VPN/SSH Tunneling:** Require access via a VPN or SSH tunnel for any remote access.
    *   **Reverse Proxy with Authentication:** Configure a reverse proxy (Nginx, Apache) with strong authentication (HTTP Basic Auth, OAuth) and authorization.
    *   **Configuration Audits:** Regularly review network configurations and firewall rules.

## Attack Surface: [2. Lack of Authentication/Authorization](./attack_surfaces/2__lack_of_authenticationauthorization.md)

*   **Description:** MailCatcher has no built-in authentication, allowing anyone with network access to view all captured emails.
*   **MailCatcher Contribution:** MailCatcher is designed for development and lacks authentication features by default.
*   **Example:** A developer shares a local network with others. Anyone on the network can access the MailCatcher interface and view emails.
*   **Impact:** Unauthorized access to emails, even within a trusted environment, can lead to information leakage.
*   **Risk Severity:** **High** (if exposed internally), **Critical** (if exposed publicly)
*   **Mitigation Strategies:**
    *   **Reverse Proxy with Authentication:** Implement a reverse proxy (Nginx, Apache) with robust authentication and authorization. This is the primary mitigation.
    *   **Network Segmentation:** Limit network access as described above.

## Attack Surface: [3. Stored Cross-Site Scripting (XSS) via Email Content](./attack_surfaces/3__stored_cross-site_scripting__xss__via_email_content.md)

*   **Description:** An attacker sends an email containing malicious JavaScript that is stored by MailCatcher and executed when a user views the email within the MailCatcher interface.
*   **MailCatcher Contribution:** MailCatcher displays email content, and if it doesn't properly sanitize this content, it can render malicious scripts.
*   **Example:** An attacker sends an email with a `<script>` tag in the body. When a developer views the email in MailCatcher, the script executes, potentially stealing cookies or redirecting the user.
*   **Impact:** Session hijacking (if authentication is added via a reverse proxy), defacement, or potentially gaining control of the user's browser.
*   **Risk Severity:** **High**
*   **Mitigation Strategies:**
    *   **Content Security Policy (CSP):** Implement a strict CSP in MailCatcher (requires code modification) to restrict script sources.
    *   **Input Sanitization/Encoding:** Ensure MailCatcher properly HTML-encodes email content (body and headers) before displaying it.
    *   **View as Plain Text:** Configure MailCatcher or user behavior to prioritize viewing emails in plain text.
    * **Regular Updates:** Apply any security patches to MailCatcher if they become available.

