# Attack Surface Analysis for rabbitmq/rabbitmq-server

## Attack Surface: [Network Exposure (Default Ports)](./attack_surfaces/network_exposure__default_ports_.md)

*   **Description:**  RabbitMQ exposes several default ports for various functionalities, making them potential entry points for attackers.
*   **How RabbitMQ Contributes:**  RabbitMQ's core functionality relies on network communication via these ports (AMQP, Management UI, Erlang distribution).
*   **Example:** An attacker scans for open port 5672 (AMQP) and attempts to connect using default credentials or exploit a known vulnerability in the AMQP protocol implementation.
*   **Impact:** Unauthorized access to the messaging system, message interception/modification, denial of service, complete system compromise.
*   **Risk Severity:** Critical (if exposed to the public internet without proper protection) / High (if exposed internally without adequate controls).
*   **Mitigation Strategies:**
    *   **Firewall Rules:**  Strictly limit access to RabbitMQ ports (5672, 15672, 25672, 4369, and any plugin-specific ports) using network firewalls.  Only allow connections from authorized client IPs and internal cluster nodes.
    *   **Disable Unnecessary Services:** If the Management UI (15672) is not needed, disable the plugin.
    *   **Network Segmentation:**  Isolate RabbitMQ servers on a dedicated network segment.
    *   **VPN/Tunneling:** For inter-node communication across untrusted networks, use a VPN or secure tunnel.
    *   **Reverse Proxy:** Place a reverse proxy in front of the Management UI (15672) for added security.

## Attack Surface: [Weak Authentication](./attack_surfaces/weak_authentication.md)

*   **Description:**  Using default or easily guessable credentials for RabbitMQ users.
*   **How RabbitMQ Contributes:** RabbitMQ relies on user authentication to control access to its resources.
*   **Example:** An attacker uses the default `guest/guest` credentials to connect to the RabbitMQ Management UI or AMQP port.
*   **Impact:** Unauthorized access to the messaging system, ability to send/receive messages, reconfigure the broker, create/delete users, queues, etc.
*   **Risk Severity:** Critical.
*   **Mitigation Strategies:**
    *   **Disable Default User:**  Disable the default `guest` user *immediately* after installation.
    *   **Strong Passwords:**  Enforce strong password policies for all RabbitMQ users.
    *   **Password Management:**  Use a secure password manager.
    *   **Client Certificate Authentication:** Implement client certificate authentication (mTLS).

## Attack Surface: [Insufficient Authorization](./attack_surfaces/insufficient_authorization.md)

*   **Description:**  Granting users more permissions than they need.
*   **How RabbitMQ Contributes:** RabbitMQ's authorization system controls which users can access which resources (vhosts, queues, exchanges).
*   **Example:** A user with read/write access to all vhosts is compromised, allowing the attacker to access and manipulate messages in *any* vhost.
*   **Impact:**  Increased blast radius of a compromised account.
*   **Risk Severity:** High.
*   **Mitigation Strategies:**
    *   **Principle of Least Privilege:**  Grant users only the *minimum* necessary permissions.
    *   **Role-Based Access Control (RBAC):**  Define roles with specific permissions.
    *   **Regular Audits:**  Periodically review and audit user permissions.
    *   **Fine-Grained Permissions:** Utilize RabbitMQ's granular permission system.

## Attack Surface: [Protocol Vulnerabilities (AMQP)](./attack_surfaces/protocol_vulnerabilities__amqp_.md)

*   **Description:**  Exploiting vulnerabilities in the AMQP protocol implementation *within the RabbitMQ server*.
*   **How RabbitMQ Contributes:** RabbitMQ *implements* the AMQP protocol for client communication.  This is distinct from vulnerabilities in *client* libraries.
*   **Example:** An attacker sends a specially crafted AMQP message that exploits a buffer overflow vulnerability *in the RabbitMQ server's AMQP parsing code*, leading to remote code execution.
*   **Impact:**  Denial of service, arbitrary code execution, data breaches, complete system compromise.
*   **Risk Severity:** High.
*   **Mitigation Strategies:**
    *   **Keep Software Updated:**  Regularly update the RabbitMQ *server* to the latest version to patch known vulnerabilities.
    *   **Monitor Security Advisories:**  Subscribe to security advisories specifically for RabbitMQ *server*.
    *   **Vulnerability Scanning:**  Use vulnerability scanners to identify potential weaknesses in your RabbitMQ *server* deployment.

## Attack Surface: [Resource Exhaustion (DoS)](./attack_surfaces/resource_exhaustion__dos_.md)

*   **Description:**  An attacker overwhelming the RabbitMQ *broker* with requests.
*   **How RabbitMQ Contributes:** RabbitMQ's performance is limited by available resources. This is a direct attack on the *server*.
*   **Example:** An attacker floods the *broker* with connections, messages, or queue declarations.
*   **Impact:**  Denial of service.
*   **Risk Severity:** High.
*   **Mitigation Strategies:**
    *   **Resource Limits:**  Configure resource limits *within RabbitMQ* (connections, queue length, message size, prefetch count).
    *   **Rate Limiting:**  Implement rate limiting on connections and message publishing *at the broker level*.
    *   **Load Balancing:**  Use a load balancer to distribute traffic across multiple RabbitMQ *nodes*.
    *   **Monitoring and Alerting:**  Monitor resource usage and set up alerts.
    *   **Dead Letter Queues:** Use dead-letter queues.
    *   **Consumer Timeouts:** Implement timeouts for consumers.

