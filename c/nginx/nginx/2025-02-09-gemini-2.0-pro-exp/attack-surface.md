# Attack Surface Analysis for nginx/nginx

## Attack Surface: [Misconfigured `root` and `alias` Directives (Directory Traversal)](./attack_surfaces/misconfigured__root__and__alias__directives__directory_traversal_.md)

*   **Description:** Incorrectly configured `root` or `alias` directives allow access to files and directories outside the intended web root.
*   **Nginx Contribution:** Nginx's core functionality of serving files based on these directives is the direct source of the vulnerability if misconfigured.
*   **Example:**  A configuration like `location /images { alias /var/www/images/; }` without a trailing slash on the location, combined with a request to `/images../secret.txt`, could expose `/var/www/secret.txt`.
*   **Impact:**  Exposure of sensitive files (configuration files, source code, system files), potentially leading to complete system compromise.
*   **Risk Severity:** Critical
*   **Mitigation Strategies:**
    *   **Developers/Users:**  Carefully review and test `root` and `alias` directives.  Use the most specific path possible.  Ensure trailing slashes are used correctly.  Avoid using `alias` when `root` is sufficient.  Test with various URL patterns to ensure no unintended access.  Use a web application firewall (WAF) with directory traversal protection.

## Attack Surface: [Weak `server_name` Configuration (Host Header Attacks)](./attack_surfaces/weak__server_name__configuration__host_header_attacks_.md)

*   **Description:**  Using a wildcard (`_`) or overly broad `server_name` allows attackers to manipulate the `Host` header, potentially bypassing security controls or causing unexpected application behavior.
*   **Nginx Contribution:** Nginx uses the `server_name` directive to determine which virtual host should handle a request, making it the central point of this vulnerability.
*   **Example:**  If `server_name` is set to `_`, an attacker could send a request with `Host: evil.com` and potentially access resources or trigger behavior intended for a different virtual host.
*   **Impact:**  Bypassing authentication, accessing internal resources, cache poisoning, application-level vulnerabilities triggered by unexpected host headers.
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   **Developers/Users:**  Define specific `server_name` values for each virtual host.  Avoid wildcards unless absolutely necessary and well-understood.  Implement a default server block that catches and rejects (returns a 444 status code, for example) requests with invalid `Host` headers.

## Attack Surface: [Insecure SSL/TLS Configuration](./attack_surfaces/insecure_ssltls_configuration.md)

*   **Description:**  Using weak ciphers, outdated protocols (SSLv3, TLS 1.0, TLS 1.1), or improperly configured certificates exposes the server to MITM attacks.
*   **Nginx Contribution:** Nginx handles the SSL/TLS encryption, making its configuration directly responsible for the security of the encrypted connection.
*   **Example:**  Using `ssl_protocols TLSv1 TLSv1.1;` allows connections using outdated and vulnerable protocols.
*   **Impact:**  Interception of sensitive data (credentials, session tokens, personal information), man-in-the-middle attacks.
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   **Developers/Users:**  Use strong ciphers and modern TLS protocols (TLS 1.2 and TLS 1.3).  Regularly update the SSL/TLS configuration based on current best practices (e.g., Mozilla's SSL Configuration Generator).  Use a valid and trusted SSL/TLS certificate.  Enable HSTS (HTTP Strict Transport Security) using the `add_header` directive.  Use tools like `sslscan` or `testssl.sh` to test the SSL/TLS configuration.

## Attack Surface: [Missing or Weak Rate Limiting (`limit_req` and `limit_conn`)](./attack_surfaces/missing_or_weak_rate_limiting___limit_req__and__limit_conn__.md)

*   **Description:**  Absence of rate limiting and connection limiting makes the server vulnerable to DoS and brute-force attacks.
*   **Nginx Contribution:** Nginx provides the `limit_req` and `limit_conn` modules for implementing rate limiting, making their proper configuration crucial for mitigating these attacks.
*   **Example:**  An attacker could send thousands of requests per second to a login page, attempting to guess passwords or overwhelm the server.
*   **Impact:**  Denial of service, successful brute-force attacks, resource exhaustion.
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   **Developers/Users:**  Implement `limit_req` and `limit_conn` directives to control the rate of requests and the number of concurrent connections.  Tune these settings appropriately for the expected traffic patterns.  Use different zones for different parts of the application (e.g., separate limits for login pages and static assets).  Consider using a WAF with more advanced DoS protection capabilities.

## Attack Surface: [Vulnerabilities in Nginx Modules (Core and Third-Party)](./attack_surfaces/vulnerabilities_in_nginx_modules__core_and_third-party_.md)

*   **Description:**  Vulnerabilities in Nginx's core modules or third-party modules can lead to various attacks, including DoS and RCE.
*   **Nginx Contribution:** Nginx's modular architecture means that vulnerabilities in any loaded module can affect the entire server.
*   **Example:**  A vulnerability in a third-party module that handles image processing could allow an attacker to execute arbitrary code by uploading a specially crafted image.
*   **Impact:**  Varies depending on the vulnerability, but can range from DoS to RCE.
*   **Risk Severity:**  High to Critical (depending on the specific vulnerability)
*   **Mitigation Strategies:**
    *   **Developers/Users:**  Keep Nginx and all installed modules updated to the latest stable versions.  Monitor security advisories and apply patches promptly.  Carefully vet any third-party modules before using them.  Choose modules from reputable sources.  Minimize the number of third-party modules used.  Use a vulnerability scanner to identify known vulnerabilities.

## Attack Surface: [Running Nginx as Root](./attack_surfaces/running_nginx_as_root.md)

* **Description:** Running with root privileges gives an attacker full system control if Nginx is compromised.
* **Nginx Contribution:** Nginx can be configured to run as any user, including root.
* **Example:** If Nginx is running as root and a vulnerability allows remote code execution, the attacker gains root access to the entire system.
* **Impact:** Complete system compromise.
* **Risk Severity:** Critical
* **Mitigation Strategies:**
    * **Developers/Users:** Run Nginx as a dedicated, unprivileged user (e.g., `nginx`, `www-data`). Use the `user` directive in the Nginx configuration file. Ensure the worker processes also run as an unprivileged user.

