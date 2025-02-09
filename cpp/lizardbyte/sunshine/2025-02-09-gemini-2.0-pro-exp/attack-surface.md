# Attack Surface Analysis for lizardbyte/sunshine

## Attack Surface: [Input Injection (Host-Level)](./attack_surfaces/input_injection__host-level_.md)

*Description:*  The ability for an attacker to inject arbitrary commands into the host operating system through Sunshine's input handling. This is the most dangerous vulnerability because it bypasses the game and targets the underlying OS.
*How Sunshine Contributes:* Sunshine's core function of translating client input to host input creates the *direct pathway* for this attack. The vulnerability lies in *how* Sunshine performs this translation.
*Example:* An attacker sends crafted input that, instead of controlling the game, executes a shell command on the host (e.g., downloading malware, creating a backdoor user).
*Impact:*  Complete compromise of the host system. Full control by the attacker.
*Risk Severity:* **Critical**
*Mitigation Strategies:*
    *   **Developers:**
        *   **Strict Input Validation (Whitelist):**  Implement a *whitelist* of allowed input characters and sequences. Reject *everything* else.  Do not rely on blacklisting.
        *   **Input Sanitization/Escaping:**  Escape or sanitize *all* input before passing it to the host OS, preventing any characters from being interpreted as commands.
        *   **Least Privilege:** Run Sunshine with the *absolute minimum* necessary privileges. Never as administrator/root unless absolutely unavoidable, and even then, isolate privileged operations.
        *   **Sandboxing:** Isolate the input handling process in a sandbox or container to limit the damage from a successful injection.
        *   **Security Audits:** Regular code reviews and penetration testing, specifically targeting input handling.
    *   **Users:**
        *   **Strong Authentication:** Use a strong, unique Sunshine password/PIN.
        *   **Network Security:** Secure your network (strong Wi-Fi password, firewall).
        *   **Monitor Host:** Watch for any unusual activity on your host system.

## Attack Surface: [Streaming Protocol Exploitation (MitM leading to Input Injection)](./attack_surfaces/streaming_protocol_exploitation__mitm_leading_to_input_injection_.md)

*Description:*  Specifically, a Man-in-the-Middle (MitM) attack on the streaming protocol that allows the attacker to *inject malicious input*. This elevates the risk of a standard MitM (which could just view the stream) to a critical level.
*How Sunshine Contributes:* Sunshine's streaming functionality is the target. The vulnerability is in the *lack of enforced, robust encryption* of the streaming protocol.
*Example:* An attacker intercepts the unencrypted stream and injects input commands, bypassing Sunshine's authentication and directly controlling the host (as in #1).
*Impact:*  Complete compromise of the host system (same as #1, but via a different attack vector).
*Risk Severity:* **Critical**
*Mitigation Strategies:*
    *   **Developers:**
        *   **Enforce Encryption:**  Make encryption (DTLS for UDP, TLS for TCP) *mandatory* and *non-configurable* by the user. Use strong, modern ciphers.
        *   **WebRTC Security:**  Adhere to all WebRTC security best practices. Ensure the WebRTC implementation is up-to-date and correctly configured.
        *   **Certificate Pinning (Consider):**  For an extra layer of security, consider certificate pinning to prevent MitM attacks even if a CA is compromised.
    *   **Users:**
        *   **Secure Network:**  Use a secure network (strong Wi-Fi password, firewall). Avoid public Wi-Fi.
        *   **Manual Port Forwarding:** If port forwarding is needed, do it manually instead of relying on UPnP.

## Attack Surface: [Web Interface Vulnerabilities (RCE)](./attack_surfaces/web_interface_vulnerabilities__rce_.md)

*Description:*  Specifically, Remote Code Execution (RCE) vulnerabilities in Sunshine's web interface. This allows an attacker to run arbitrary code on the host. Other web vulnerabilities (CSRF, etc.) are less critical *in the context of Sunshine*, as they usually lead to configuration changes, not full system compromise.
*How Sunshine Contributes:* Sunshine's built-in web server for configuration *is* the attack surface.
*Example:* An attacker exploits a vulnerability in the web server or a library it uses to upload and execute a malicious script.
*Impact:*  Complete compromise of the host system.
*Risk Severity:* **Critical**
*Mitigation Strategies:*
    *   **Developers:**
        *   **Secure Web Development:** Follow OWASP Top 10 and other secure coding practices for web applications.
        *   **Regular Updates:** Keep the web server and *all* its dependencies (libraries) meticulously up-to-date.
        *   **Least Privilege:** Run the web server with the *minimum* necessary privileges.
        *   **Input Validation (Web):**  Strictly validate all input received through the web interface.
        *   **Vulnerability Scanning:** Use web application vulnerability scanners.
    *   **Users:**
        *   **Strong Password:** Use a strong, unique password for the web interface.
        *   **HTTPS:**  Ensure you are accessing the web interface over HTTPS (if enabled).
        *   **Disable if Unnecessary:** If you don't *need* the web interface, disable it entirely.

## Attack Surface: [Dependency Vulnerabilities (RCE)](./attack_surfaces/dependency_vulnerabilities__rce_.md)

*Description:* Remote Code Execution (RCE) vulnerabilities in third-party libraries used by Sunshine.
*How Sunshine Contributes:* Sunshine's reliance on external libraries (FFmpeg, SDL, WebRTC components, etc.) directly introduces this risk.
*Example:* A vulnerability in a specific version of FFmpeg used by Sunshine allows an attacker to execute code when processing a specially crafted video stream.
*Impact:* Complete compromise of the host system.
*Risk Severity:* **Critical**
*Mitigation Strategies:*
    *   **Developers:**
        *   **Dependency Management:** Maintain a precise inventory of all dependencies and their versions.
        *   **Regular Updates:** Keep *all* dependencies up-to-date, applying security patches immediately.
        *   **Vulnerability Scanning:** Use tools to scan for known vulnerabilities in dependencies.
        *   **Static Analysis:** Use static analysis tools to find potential vulnerabilities in how dependencies are used.
    *   **Users:**
        *   **Keep Sunshine Updated:** Install the latest version of Sunshine to get the newest dependency updates.

