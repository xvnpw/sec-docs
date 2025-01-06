# Attack Surface Analysis for akhikhl/gretty

## Attack Surface: [Exposure of Development Web Server](./attack_surfaces/exposure_of_development_web_server.md)

**Description:** The web server launched by Gretty for development purposes is accessible from unintended networks.

**How Gretty Contributes:** Gretty, by default or through configuration, might bind the server to `0.0.0.0` or use non-loopback interfaces, making it reachable beyond the developer's machine.

**Example:** A developer starts their application with Gretty, and due to a misconfigured Gretty setting, someone on the local network or even the internet can access the development application's endpoints.

**Impact:** Information disclosure, access to development-stage data, potential exploitation of application vulnerabilities on a less secured instance, denial of service against the development environment.

**Risk Severity:** High

**Mitigation Strategies:**
* Configure Gretty to bind the development server to `127.0.0.1` (localhost) only.
* Utilize host-based firewalls to restrict access to the development server's port.
* Avoid running Gretty on publicly accessible networks without proper security measures.

## Attack Surface: [Exposure of Debug Ports (JDWP)](./attack_surfaces/exposure_of_debug_ports__jdwp_.md)

**Description:** Gretty can be configured to expose Java Debug Wire Protocol (JDWP) ports, allowing remote debugging. If not properly secured, this can be exploited.

**How Gretty Contributes:** Gretty provides configuration options to enable and specify the port for JDWP. If enabled without proper access control, it becomes an attack vector.

**Example:** A developer starts Gretty with debugging enabled, and an attacker on the same network connects to the JDWP port, gaining control over the Java Virtual Machine (JVM).

**Impact:** Remote code execution, access to sensitive data in memory, ability to manipulate the application's state.

**Risk Severity:** Critical

**Mitigation Strategies:**
* Avoid enabling debug ports in Gretty configurations unless absolutely necessary.
* If debugging is required, bind the debug port to `127.0.0.1` to restrict access to the local machine only.

