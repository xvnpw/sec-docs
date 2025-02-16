# Attack Surface Analysis for habitat-sh/habitat

## Attack Surface: [Supervisor Compromise (Direct Process Attack)](./attack_surfaces/supervisor_compromise__direct_process_attack_.md)

**Description:** An attacker gains direct control of the Habitat Supervisor process running on a host.
**How Habitat Contributes:** The Supervisor runs with elevated privileges (often root-equivalent) to manage packages and their lifecycle. This is inherent to Habitat's design and makes it a high-value target.
**Example:** An attacker exploits a vulnerability in the Supervisor's code (e.g., a buffer overflow in the HTTP API handling) to gain shell access on the host as the Supervisor's user.
**Impact:** Complete system compromise. The attacker can deploy malicious packages, modify existing packages, exfiltrate data, and pivot to other systems.
**Risk Severity:** Critical
**Mitigation Strategies:**
    *   **Least Privilege:** Run the Supervisor as a *non-root* user with the absolute minimum necessary permissions. Create a dedicated user specifically for the Supervisor.
    *   **System Hardening:** Apply OS-level hardening techniques (e.g., SELinux/AppArmor, seccomp profiles) to restrict the Supervisor's capabilities even if compromised.
    *   **Vulnerability Management:** Keep the Supervisor itself updated to the latest version to patch any known vulnerabilities.
    *   **HIDS/HIPS:** Deploy host-based intrusion detection/prevention systems to monitor the Supervisor process for anomalous behavior.
    *   **Network Segmentation:** Isolate the host running the Supervisor on a dedicated network segment with strict firewall rules.

## Attack Surface: [Unauthorized Package Deployment/Modification (via Builder or Supervisor)](./attack_surfaces/unauthorized_package_deploymentmodification__via_builder_or_supervisor_.md)

**Description:** An attacker deploys a malicious package or modifies an existing package, leading to the execution of untrusted code. This directly targets Habitat's package management functionality.
**How Habitat Contributes:** Habitat's core function is package management.  If the mechanisms for controlling package deployment (Builder and Supervisor interaction) are bypassed, this is a direct attack on Habitat's purpose.
**Example:**
    *   **Scenario A (Builder):** An attacker gains access to a private Builder depot and uploads a malicious package disguised as a legitimate update.
    *   **Scenario B (Supervisor):** An attacker compromises a network service that has access to the Supervisor's API and uses it to install a malicious package.
**Impact:** Code execution under the context of the application, potentially leading to data breaches, system compromise, or lateral movement.
**Risk Severity:** High
**Mitigation Strategies:**
    *   **Package Signing:** *Always* sign packages with a trusted origin key. Configure the Supervisor to *reject* unsigned packages or packages signed by untrusted keys. This is the *primary* defense, and is directly related to Habitat's functionality.
    *   **Origin Verification:** Configure the Supervisor to *only* pull packages from trusted Builder depots (using the `-u` or `--url` flag). This is a Habitat-specific configuration.
    *   **Strong Authentication:** Implement strong authentication (e.g., API keys with limited scope, multi-factor authentication) for both Builder and the Supervisor's API.
    *   **Network Segmentation:** Isolate Builder and the Supervisor's API from untrusted networks.
    *   **RBAC (Role-Based Access Control):** Implement RBAC for Builder to limit who can publish packages.

## Attack Surface: [Malicious `run` Hook Execution](./attack_surfaces/malicious__run__hook_execution.md)

**Description:** An attacker crafts a package with a malicious `run` hook (or other lifecycle hook) that executes arbitrary code when the package is started. This exploits Habitat's hook system.
**How Habitat Contributes:** Habitat's hook system provides a mechanism for executing code during package lifecycle events. This mechanism, *specific to Habitat*, can be abused.
**Example:** A package's `run` hook contains a command that downloads and executes a remote shell script, giving the attacker control.
**Impact:** Code execution with the privileges of the service user, potentially leading to privilege escalation or system compromise.
**Risk Severity:** High
**Mitigation Strategies:**
    *   **Trusted Sources:** Only use packages from trusted sources (official depots, your own rigorously controlled private depot).
    *   **Code Review:** *Manually review* the `plan.sh` and all hook scripts (especially `run`) of *every* package before deployment, particularly if sourced externally. Look for obfuscated code, network connections, or suspicious commands.
    *   **Least Privilege (Hooks):** Ensure that hooks run with the *minimum* necessary privileges. Avoid running hooks as root if at all possible.  Use `pkg_svc_user` and `pkg_svc_group` appropriately. These are Habitat-specific settings.
    *   **Sandboxing (Advanced):** Consider advanced techniques to sandbox hook execution (e.g., using containers or specialized sandboxing tools), but this adds complexity.

## Attack Surface: [Supervisor API Exploitation](./attack_surfaces/supervisor_api_exploitation.md)

**Description:** An attacker exploits vulnerabilities in the Supervisor's HTTP API to control the Supervisor or the managed applications.
**How Habitat Contributes:** The Supervisor exposes an API for management, which is a *core component of Habitat*, and if insecure, presents an attack vector.
**Example:** An attacker sends a crafted HTTP request to the Supervisor's API that triggers a buffer overflow, allowing them to execute arbitrary code.
**Impact:** Control over the Supervisor and all managed applications, leading to system compromise.
**Risk Severity:** High
**Mitigation Strategies:**
    *   **Secure API Binding:** Bind the API to a *secure interface* (e.g., `localhost` or a Unix socket). *Never* expose the API directly to untrusted networks without additional protection. This is a direct configuration of the Habitat Supervisor.
    *   **TLS Encryption:** If the API must be exposed over a network, *always* use TLS encryption to protect communication.
    *   **Authentication:** Implement strong authentication for the API (e.g., API keys).
    *   **Input Validation:** Rigorously validate *all* input to the API to prevent injection attacks.
    *   **Regular Security Audits:** Conduct regular security audits of the Supervisor's API implementation.

