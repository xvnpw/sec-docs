# Attack Surface Analysis for gollum/gollum

## Attack Surface: [Unauthorized Wiki Content Access/Modification](./attack_surfaces/unauthorized_wiki_content_accessmodification.md)

*Description:* Attackers gain unauthorized access to create, modify, or delete wiki pages, bypassing intended access controls.
*Gollum Contribution:* Gollum's *primary function* is wiki editing.  Its design centers around providing this functionality, making unauthorized access the core attack vector. The Git backend provides an audit trail *after* the fact, but doesn't prevent the initial unauthorized action.
*Example:* An attacker bypasses authentication and defaces the homepage or inserts malicious links into important pages.
*Impact:* Data loss, data corruption, reputational damage, potential spread of malware (if links are inserted), potential compromise of other systems (if credentials or sensitive information are stored in the wiki).
*Risk Severity:* **Critical**
*Mitigation Strategies:*
    *   **Strong Authentication:** Implement robust authentication (e.g., OmniAuth with a secure provider, strong password policies with HTTP Basic, or integration with an existing authentication system).  This is the *primary* defense.
    *   **Granular Authorization:** Use page-level permissions (if supported by the authentication method) to restrict access to specific pages or sections. Gollum's support for this depends on the chosen authentication/authorization backend.
    *   **Reverse Proxy:** Consider a reverse proxy (Nginx, Apache) for more advanced authentication/authorization (2FA, IP whitelisting). This adds a layer of defense *before* requests reach Gollum.
    *   **Regular Audits:** Regularly review user accounts and permissions.
    *   **Principle of Least Privilege:** Grant users only the minimum necessary permissions.

## Attack Surface: [Direct Git Repository Manipulation](./attack_surfaces/direct_git_repository_manipulation.md)

*Description:* Attackers gain direct access to the underlying Git repository (e.g., via SSH, filesystem access) and bypass Gollum's web interface controls.
*Gollum Contribution:* Gollum's architecture *fundamentally relies* on Git. The Git repository *is* the wiki data. This direct access bypasses any web-based controls Gollum might have.
*Example:* An attacker with SSH access modifies the Git repository directly to insert malicious content or alter commit history.
*Impact:* Complete compromise of the wiki content and history, potential introduction of malicious code, denial of service.
*Risk Severity:* **Critical**
*Mitigation Strategies:*
    *   **Secure SSH Access:** Use strong SSH key authentication; disable password-based SSH.
    *   **Restrict Filesystem Permissions:** Ensure *only* authorized users/processes can access the Git repository directory. This is crucial.
    *   **Dedicated Git Server:** Consider a dedicated Git server (GitLab, GitHub, Gitea) for robust access controls and auditing. This moves the repository management outside of Gollum's direct control.
    *   **Regular Backups:** Back up the Git repository to a secure location.
    *   **Monitoring:** Monitor Git repository access logs.

## Attack Surface: [Malicious File Uploads (If Enabled)](./attack_surfaces/malicious_file_uploads__if_enabled_.md)

*Description:* Attackers upload malicious files (scripts, executables) disguised as legitimate files.
*Gollum Contribution:* Gollum *allows* file uploads to be enabled, but it's not the default.  The *choice* to enable uploads, and how they are handled within the Git repository, is the Gollum-specific aspect.
*Example:* An attacker uploads a PHP shell disguised as a .jpg, then accesses it to gain server control.
*Impact:* Server compromise, data exfiltration, denial of service, client-side attacks.
*Risk Severity:* **High** (if uploads are enabled)
*Mitigation Strategies:*
    *   **Disable Uploads (Preferred):** If not essential, disable them. This is the most secure option.
    *   **Strict File Type Validation:** *Never* trust extensions. Use MIME type *and* magic number checks.
    *   **Store Outside Webroot:** Store uploads *outside* the web server's document root. Serve them through a dedicated script.
    *   **Anti-Malware Scanning:** Scan all uploaded files.
    *   **File Size Limits:** Enforce strict size limits.

## Attack Surface: [Unsafe Markup Injection (XSS)](./attack_surfaces/unsafe_markup_injection__xss_.md)

*Description:* Attackers inject malicious code (e.g., JavaScript) via unsafe markup.
*Gollum Contribution:* Gollum's vulnerability depends on the *configured markup language and sanitization settings*. Allowing raw HTML or using weak sanitization makes XSS possible. This is a configuration choice within Gollum.
*Example:* An attacker inserts a `<script>` tag with malicious JavaScript.
*Impact:* Session hijacking, credential theft, defacement, redirection, data exfiltration.
*Risk Severity:* **High** (if unsafe markup is allowed)
*Mitigation Strategies:*
    *   **Safe Markup Language:** Use a safe language by default (Markdown, reStructuredText).
    *   **Robust HTML Sanitization:** If allowing HTML, use a strong, up-to-date sanitizer (Gollum uses `sanitize`; configure it correctly).
    *   **Content Security Policy (CSP):** Implement a strict CSP. This is a *critical* defense-in-depth measure, even with sanitization.
    *   **Input Validation:** Validate input *before* markup processing.
    *   **Output Encoding:** Ensure proper output encoding.

## Attack Surface: [Information Disclosure (.git directory)](./attack_surfaces/information_disclosure___git_directory_.md)

*Description:* The `.git` directory is accidentally exposed via the web server.
*Gollum Contribution:* Gollum *uses* Git, so the `.git` directory's *existence* is inherent. The vulnerability is in the *exposure* of this directory, which is a web server configuration issue, but directly related to Gollum's architecture.
*Example:* Misconfigured web server allows access to `http://example.com/wiki/.git/`.
*Impact:* Leakage of sensitive information (previous page versions, commit history).
*Risk Severity:* **High**
*Mitigation Strategies:*
    *   **Web Server Configuration:** Configure the web server (Apache, Nginx) to *explicitly deny* access to the `.git` directory. This is a *critical* and standard security practice, but it's directly relevant because of Gollum's Git backend.

