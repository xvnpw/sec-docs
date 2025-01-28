# Attack Surface Analysis for rabbitmq/rabbitmq-server

## Attack Surface: [Unencrypted AMQP Traffic](./attack_surfaces/unencrypted_amqp_traffic.md)

*   **Description:** Communication over the AMQP protocol without TLS/SSL encryption.
*   **RabbitMQ Contribution:** RabbitMQ, by default, can be configured to operate over unencrypted AMQP on port 5672. If TLS is not explicitly enabled, traffic is vulnerable.
*   **Example:** An attacker on the same network as the RabbitMQ server and clients intercepts network traffic and reads sensitive messages, including credentials or business data being exchanged.
*   **Impact:** Confidentiality breach, data leakage, credential compromise, potential for further attacks based on intercepted information.
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   **Enforce TLS/SSL for AMQP:** Configure RabbitMQ to use TLS/SSL for all AMQP connections. This encrypts communication between clients and the server, and between nodes in a cluster.
    *   **Disable Plain AMQP Port:** If TLS is enforced, consider disabling the plain AMQP port (5672) to prevent accidental or intentional unencrypted connections.

## Attack Surface: [Management UI Authentication Bypass/Vulnerabilities](./attack_surfaces/management_ui_authentication_bypassvulnerabilities.md)

*   **Description:** Security flaws in the RabbitMQ Management UI that allow unauthorized access or actions.
*   **RabbitMQ Contribution:** The Management UI is a built-in plugin of RabbitMQ, providing web-based administration. Vulnerabilities in this UI directly expose the RabbitMQ server.
*   **Example:** A Cross-Site Scripting (XSS) vulnerability in the Management UI is exploited to inject malicious JavaScript. An administrator browsing the UI with a compromised browser executes the script, allowing the attacker to steal session cookies and gain administrative access.
*   **Impact:** Full compromise of the RabbitMQ server, including control over exchanges, queues, users, and messages. Potential data manipulation or denial of service.
*   **Risk Severity:** Critical
*   **Mitigation Strategies:**
    *   **Enforce HTTPS for Management UI:** Always run the Management UI over HTTPS to protect credentials and session cookies in transit.
    *   **Regularly Update RabbitMQ:** Keep RabbitMQ server and its plugins updated to the latest versions to patch known vulnerabilities in the Management UI.
    *   **Strong Passwords and User Management:** Enforce strong passwords for all Management UI users and follow the principle of least privilege when assigning roles.
    *   **Disable Guest User:** Disable or change the password for the default `guest` user immediately.

## Attack Surface: [Default `guest` User Credentials](./attack_surfaces/default__guest__user_credentials.md)

*   **Description:** Using the default `guest` user with its well-known password for access to RabbitMQ.
*   **RabbitMQ Contribution:** RabbitMQ, by default, creates a `guest` user with the password `guest` and grants it default permissions. This is intended for initial setup but is a major security risk in production.
*   **Example:** An attacker attempts to connect to RabbitMQ using the `guest` username and `guest` password from anywhere on the network (or even the internet if the ports are exposed). Successful login grants them access to RabbitMQ resources based on the default permissions of the `guest` user.
*   **Impact:** Unauthorized access to RabbitMQ, potentially allowing message manipulation, queue deletion, or denial of service, depending on the `guest` user's effective permissions.
*   **Risk Severity:** Critical
*   **Mitigation Strategies:**
    *   **Disable the `guest` User:** The most secure approach is to completely disable the `guest` user.
    *   **Change `guest` User Password:** If disabling is not immediately feasible, change the `guest` user's password to a strong, unique password.
    *   **Restrict `guest` User Permissions:** If the `guest` user must remain enabled for specific reasons, significantly restrict its permissions to the absolute minimum required.

## Attack Surface: [Plugin Vulnerabilities](./attack_surfaces/plugin_vulnerabilities.md)

*   **Description:** Security vulnerabilities present in RabbitMQ plugins, whether built-in or third-party.
*   **RabbitMQ Contribution:** RabbitMQ's plugin architecture allows extending functionality, but plugins can introduce vulnerabilities if not properly developed, maintained, or audited.
*   **Example:** A vulnerability in a specific RabbitMQ plugin (e.g., a protocol plugin like MQTT or STOMP, or a management plugin) is discovered and exploited by an attacker to gain unauthorized access or cause a denial of service.
*   **Impact:**  Varies depending on the plugin and vulnerability. Could range from denial of service to full server compromise, data leakage, or privilege escalation.
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   **Minimize Plugin Usage:** Only enable plugins that are strictly necessary for the application's functionality. Disable unused plugins to reduce the attack surface.
    *   **Use Official and Trusted Plugins:** Prefer using official RabbitMQ plugins or plugins from trusted and reputable sources.
    *   **Keep Plugins Updated:** Regularly update all enabled plugins to the latest versions to patch known vulnerabilities.
    *   **Monitor Plugin Security Advisories:** Subscribe to security advisories and mailing lists related to RabbitMQ and its plugins to stay informed about potential vulnerabilities.

