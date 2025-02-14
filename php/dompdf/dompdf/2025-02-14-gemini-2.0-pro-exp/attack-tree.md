# Attack Tree Analysis for dompdf/dompdf

Objective: To achieve Remote Code Execution (RCE) on the server hosting the application using dompdf, or to exfiltrate sensitive data accessible to the server.

## Attack Tree Visualization

```
                                      +-------------------------------------+
                                      |  Compromise Application via dompdf  |
                                      +-------------------------------------+
                                                  /       |       \
                                                 /        |        \
                                                /         |         \
                      +-------------------------+          |          +-------------------------+
                      |     Achieve RCE        |          |          |  Exfiltrate Sensitive Data |
                      +-------------------------+          |          +-------------------------+
                      /        |        \                 |          /        |        \
                     /         |         \                |         /         |         \
                    /          |          \               |        /          |          \
+-------------------+          |          \               | +-------------+-----+ +-------------+-----+ +-------------+-----+
| Exploit Known   |          |           \              | |  SSRF via    | |  Read Local   | |  Access       |
| dompdf CVEs     |          |            \             | |  @font-face   | |  Files via    | |  Network/     |
+-------------------+          |             \            | |  or          | |  CSS/HTML     | |  Metadata     |
       |                      |              \           | |  <link>      | |  Injection    | |               |
       |                      |               \          | |  [CRITICAL]  | | [CRITICAL]    | | [CRITICAL]    |
       |                      |                \         | +-------------+-----+ +-------------+-----+ +-------------+-----+
       |                      |                 \        |
       |                      |                  \       |
       | +----------------+   |                   \      |
       | |  CVE-XXXX-YYYY |   |                    \     |
       | | (Specific     |   |                     \    |
       | |  RCE CVE)    |   |                      \   |
       | +----------------+   |                       \  |
       | [CRITICAL]         |                        \ |
       |                      |                         \|
       |                      |                          +
       |                      |
       +-----------------------------------------------------------+
       |  Abuse PHP Code Injection Vulnerabilities in User Input  |
       +-----------------------------------------------------------+
              |
              |  (If user input is directly embedded in HTML/CSS
              |   passed to dompdf without proper sanitization/escaping)
              |
       +-------------+-----+
       |  Inject PHP   |
       |  Code via    |
       |  HTML/CSS    |
       +-------------+-----+ [CRITICAL]

```

## Attack Tree Path: [1. Exploit Known dompdf CVEs (RCE Path)](./attack_tree_paths/1__exploit_known_dompdf_cves__rce_path_.md)

*   **Description:** Attackers leverage publicly disclosed vulnerabilities in dompdf, specifically those that allow for Remote Code Execution (RCE). These vulnerabilities are often documented with a CVE (Common Vulnerabilities and Exposures) identifier.
*   **Critical Node:** `CVE-XXXX-YYYY (Specific RCE CVE)` - Represents a specific, known RCE vulnerability in dompdf.
*   **Attack Steps:**
    1.  Identify the version of dompdf being used by the target application.
    2.  Search vulnerability databases (NVD, CVE Mitre, etc.) for known RCE vulnerabilities affecting that version.
    3.  Obtain or craft exploit code targeting the specific CVE.
    4.  Deliver the exploit payload to the application (e.g., through a crafted form submission, URL parameter, or other input vector).
    5.  If successful, the exploit triggers the vulnerability, allowing the attacker to execute arbitrary code on the server.
*   **Mitigation:**
    *   **Primary:** Immediately patch dompdf to the latest version.  This is the most effective defense.
    *   **Secondary:** Implement a Web Application Firewall (WAF) with rules to detect and block known exploit patterns.  This provides a layer of defense but is not a substitute for patching.
    *   **Secondary:** Regularly scan the application for vulnerabilities using a vulnerability scanner.

## Attack Tree Path: [2. Abuse PHP Code Injection Vulnerabilities in User Input (RCE Path)](./attack_tree_paths/2__abuse_php_code_injection_vulnerabilities_in_user_input__rce_path_.md)

*   **Description:** Attackers inject malicious PHP code into the HTML or CSS content that is passed to dompdf. This occurs when the application fails to properly sanitize or escape user-supplied data before embedding it in the HTML/CSS.
*   **Critical Node:** `Inject PHP Code via HTML/CSS` - Represents the point where the attacker successfully injects the malicious code.
*   **Attack Steps:**
    1.  Identify input fields or parameters that are used to generate the HTML/CSS content processed by dompdf.
    2.  Craft a malicious payload containing PHP code (e.g., `<?php system($_GET['cmd']); ?>`).
    3.  Submit the payload through the identified input vector.
    4.  If the application does not properly sanitize the input, the PHP code will be embedded in the HTML/CSS.
    5.  When dompdf processes the content, the injected PHP code will be executed by the server, granting the attacker RCE.
*   **Mitigation:**
    *   **Primary:** Implement strict input validation and context-aware escaping.  Use a templating engine with automatic escaping (e.g., Twig, Blade) to prevent accidental inclusion of raw user input.
    *   **Primary:** Use a dedicated HTML/CSS sanitizer library to remove any potentially dangerous code before passing the content to dompdf.
    *   **Secondary:** Use a WAF to detect and block common PHP code injection patterns.

## Attack Tree Path: [3. SSRF via `@font-face` or `<link>` (Data Exfiltration Path)](./attack_tree_paths/3__ssrf_via__@font-face__or__link___data_exfiltration_path_.md)

*   **Description:** Attackers exploit dompdf's ability to make external requests (if `isRemoteEnabled` is true) to access internal resources, read local files, or interact with other servers. This is done through the `@font-face` rule in CSS or the `<link>` tag in HTML.
*   **Critical Node:** `SSRF via @font-face or <link>` - Represents the point where dompdf is tricked into making the unauthorized request.
*   **Attack Steps:**
    1.  Identify an injection point where CSS or HTML can be manipulated.
    2.  Craft a malicious CSS rule (e.g., `@font-face { src: url('gopher://internal-server:port/...'); }`) or HTML tag (e.g., `<link rel="stylesheet" href="file:///etc/passwd">`).
    3.  Inject the crafted code into the application.
    4.  If `isRemoteEnabled` is true, dompdf will attempt to fetch the resource specified in the malicious URL.
    5.  The attacker can then potentially access internal services, read local files, or exfiltrate data.
*   **Mitigation:**
    *   **Primary:** Set `isRemoteEnabled = false` in the dompdf configuration. This disables all external requests, effectively preventing SSRF.
    *   **Secondary (if `isRemoteEnabled` is required):** Implement a strict URL whitelist that only allows requests to known, trusted resources.
    *   **Secondary:** Use network segmentation to limit the server's access to internal resources.

## Attack Tree Path: [4. Read Local Files via CSS/HTML Injection (Data Exfiltration Path)](./attack_tree_paths/4__read_local_files_via_csshtml_injection__data_exfiltration_path_.md)

*   **Description:** Similar to SSRF, but specifically targets local files using the `file://` scheme.
*   **Critical Node:** `Read Local Files via CSS/HTML Injection` - Represents the point where dompdf is tricked into accessing a local file.
*   **Attack Steps:**
    1.  Identify an injection point for CSS or HTML.
    2.  Craft a malicious payload using the `file://` scheme (e.g., `<link rel="stylesheet" href="file:///etc/passwd">`).
    3.  Inject the payload.
    4.  If `isRemoteEnabled` is true and input sanitization is weak, dompdf will attempt to read the specified local file.
    5.  The attacker may be able to retrieve the contents of the file.
*   **Mitigation:**
    *   **Primary:** Set `isRemoteEnabled = false`.
    *   **Primary:** Implement strict input sanitization to prevent injection of the `file://` scheme.
    *   **Secondary:** Ensure the web server user has the least privilege necessary and cannot access sensitive files.

## Attack Tree Path: [5. Access Network Resources / Server Metadata (Data Exfiltration Path)](./attack_tree_paths/5__access_network_resources__server_metadata__data_exfiltration_path_.md)

*   **Description:** Attackers leverage SSRF to access internal network resources or cloud instance metadata (e.g., AWS, Azure, GCP).
*   **Critical Node:** `Access Network Resources / Server Metadata` - Represents the point where dompdf is used to access these sensitive resources.
*   **Attack Steps:**
    1.  Identify an injection point.
    2.  Craft a malicious payload targeting the metadata service or internal network resources (e.g., `@font-face { src: url('http://169.254.169.254/latest/meta-data/'); }`).
    3.  Inject the payload.
    4.  If `isRemoteEnabled` is true, dompdf will make the request.
    5.  The attacker may be able to retrieve sensitive information, such as cloud credentials or configuration data.
*   **Mitigation:**
    *   **Primary:** Set `isRemoteEnabled = false`.
    *   **Secondary:** Use IAM roles/service accounts with the principle of least privilege.
    *   **Secondary:** Implement network segmentation to isolate the application from sensitive cloud resources.

