# Mitigation Strategies Analysis for containers/podman

## Mitigation Strategy: [Rootless Mode by Default](./mitigation_strategies/rootless_mode_by_default.md)

**Mitigation Strategy:** Enforce Rootless Podman Operation

**Description:**
1.  **User Setup:** Guide users through the one-time setup process for rootless Podman, including configuring subuid/subgid mappings (`/etc/subuid`, `/etc/subgid`). Provide scripts to automate this setup where possible.  This is a *Podman-related* setup, even though it involves system files.
2.  **`podman run` Modification:**  Ensure all `podman run` (and related commands like `podman create`, `podman-compose`) commands are executed *without* `sudo` and by non-root users.  This is the core of using rootless Podman.
3.  **Verification (within Podman):** Use `podman inspect <container_id> | jq '.[0].State.Rootless'` to programmatically verify that a container is running in rootless mode.  This is a direct Podman command check.
4.  **Migration:** Use `podman-system-migrate` (a Podman utility) to help transition existing rootful containers to rootless.

**Threats Mitigated:**
*   **Container Breakout (High Severity):** If a container is compromised, the attacker gains root privileges on the host if running rootful.
*   **Privilege Escalation (High Severity):** Vulnerabilities within the container runtime or kernel could be exploited to gain root access on the host if running rootful.
*   **Host Resource Access (High Severity):** A compromised, rootful container could access sensitive host files, directories, or devices.

**Impact:**
*   **Container Breakout:** Risk reduced from *High* to *Low*.
*   **Privilege Escalation:** Risk reduced from *High* to *Low*.
*   **Host Resource Access:** Risk reduced from *High* to *Low*.

**Currently Implemented:**
*   Basic examples of rootless usage are included in the developer onboarding guide.

**Missing Implementation:**
*   Automated verification using `podman inspect` in CI/CD is not yet implemented.
*   Consistent use of rootless `podman run` commands is not enforced.
*   Migration assistance using `podman-system-migrate` is lacking.

## Mitigation Strategy: [User Namespace Configuration](./mitigation_strategies/user_namespace_configuration.md)

**Mitigation Strategy:** Secure User Namespace Mapping

**Description:**
1.  **`--userns=auto`:** Use the `--userns=auto` flag with `podman run` and related commands whenever possible. This is the *primary* Podman-direct action.
2.  **Manual Mapping (with Podman flags):** If manual mapping is required, use the `--userns` flag with specific UID/GID mappings, *directly* within the `podman run` command.  Example: `--userns=keep-id:uid=1000,gid=1000` or `--userns=map:1000:1000:1`.  The key here is that the configuration is done *through* Podman.
3.  **Validation (using Podman):** Use `podman inspect` to examine the `UsernsMode` and related fields to verify the user namespace configuration *after* the container is created.

**Threats Mitigated:**
*   **Privilege Escalation (Medium Severity):**
*   **Host Resource Access (Medium Severity):**

**Impact:**
*   **Privilege Escalation:** Risk reduced from *Medium* to *Low*.
*   **Host Resource Access:** Risk reduced from *Medium* to *Low*.

**Currently Implemented:**
*   The project wiki mentions `--userns=auto`.

**Missing Implementation:**
*   Consistent use of `--userns=auto` is not enforced.
*   Guidelines and validation for manual `--userns` usage are not in place.
*   Verification using `podman inspect` is not automated.

## Mitigation Strategy: [Capabilities Restriction](./mitigation_strategies/capabilities_restriction.md)

**Mitigation Strategy:** Minimize Granted Capabilities

**Description:**
1.  **`--cap-drop=all`:**  Start all `podman run` (and related) commands with `--cap-drop=all`. This is the fundamental Podman-specific action.
2.  **`--cap-add`:**  Use `--cap-add` *only* to add back the *absolutely necessary* capabilities, identified through analysis.  This is also a direct Podman flag.
3.  **Verification (with Podman):** Use `podman inspect` and examine the `CapAdd` and `CapDrop` fields to verify the applied capabilities.

**Threats Mitigated:**
*   **Container Breakout (Medium Severity):**
*   **Privilege Escalation (Medium Severity):**

**Impact:**
*   **Container Breakout:** Risk reduced from *Medium* to *Low*.
*   **Privilege Escalation:** Risk reduced from *Medium* to *Low*.

**Currently Implemented:**
*   Some basic capability restrictions are applied in `docker-compose.yml` files.

**Missing Implementation:**
*   `--cap-drop=all` is not consistently used.
*   Systematic capability analysis is not performed.
*   Verification using `podman inspect` is not automated.

## Mitigation Strategy: [Seccomp Profiles](./mitigation_strategies/seccomp_profiles.md)

**Mitigation Strategy:** Restrict System Calls

**Description:**
1.  **Default Profile:** Acknowledge the use of the default seccomp profile (implicit in `podman run`).
2.  **`--security-opt seccomp=<profile.json>`:** If a custom profile is needed, use the `--security-opt seccomp=<profile.json>` flag with `podman run` (and related commands). This is the *direct* Podman interaction.
3.  **Verification (with Podman):** Use `podman inspect` and examine the `SeccompProfilePath` field to verify the applied seccomp profile.

**Threats Mitigated:**
*   **Kernel Exploits (High Severity):**
*   **Zero-Day Exploits (High Severity):**

**Impact:**
*   **Kernel Exploits:** Risk reduced.
*   **Zero-Day Exploits:** Risk reduced.

**Currently Implemented:**
*   Podman's default seccomp profile is used (implicitly).

**Missing Implementation:**
*   Custom seccomp profiles (`--security-opt seccomp`) are not used.
*   Verification using `podman inspect` is not automated.

## Mitigation Strategy: [Read-Only Root Filesystem](./mitigation_strategies/read-only_root_filesystem.md)

**Mitigation Strategy:** Implement Read-Only Root Filesystem

**Description:**
1.  **`--read-only`:** Use the `--read-only` flag with `podman run` (and related commands). This is the core Podman-specific action.
2.  **`-v` or `--volume`:** Use volume mounts (`-v` or `--volume`) *in conjunction with* `--read-only` to provide writable areas for the application. This is also a direct Podman flag.
3.  **`--tmpfs`:** Use `--tmpfs` *in conjunction with* `--read-only` for temporary, non-persistent writable areas. This is a direct Podman flag.

**Threats Mitigated:**
*   **Malware Installation (Medium Severity):**
*   **Persistent Threats (Medium Severity):**
*   **Configuration Tampering (Medium Severity):**

**Impact:**
*   **Malware Installation:** Risk reduced.
*   **Persistent Threats:** Risk reduced.
*   **Configuration Tampering:** Risk reduced.

**Currently Implemented:**
*   Not implemented.

**Missing Implementation:**
*   `--read-only`, `-v`, and `--tmpfs` are not used in this combination.

## Mitigation Strategy: [Image Provenance and Signing (Limited Podman Direct Actions)](./mitigation_strategies/image_provenance_and_signing__limited_podman_direct_actions_.md)

**Mitigation Strategy:** Verify Image Signatures (using `podman` commands)

**Description:**
1. **`podman image trust`**: Use `podman image trust show/set/modify` to configure trust policies for registries. This is a *direct* Podman command for managing trust.
2. **`podman pull --signature-policy`**: Use `podman pull` with a signature policy file to enforce signature verification during image pulls. This is a *direct* Podman command.
3. **`skopeo` (Podman-related):** While `skopeo` is a separate tool, it's often used *in conjunction with* Podman for image inspection and signature verification. It's included here because it's closely tied to Podman workflows.

**Threats Mitigated:**
*   **Image Tampering (High Severity):**
*   **Supply Chain Attacks (High Severity):**

**Impact:**
*   **Image Tampering:** Risk reduced.
*   **Supply Chain Attacks:** Risk reduced.

**Currently Implemented:**
*   The project uses a private container registry.

**Missing Implementation:**
*   `podman image trust` and `--signature-policy` are not used.

## Mitigation Strategy: [Avoid Host Network Mode](./mitigation_strategies/avoid_host_network_mode.md)

**Mitigation Strategy:** Prohibit Host Network Mode

**Description:**
1.  **Policy (and Podman enforcement):** Enforce a policy *against* using `--network=host` with `podman run` (and related commands).  The enforcement is done by *not* using this flag.
2.  **Verification (with Podman):** Use `podman inspect` and check the `NetworkMode` field.  It should *not* be `host`.

**Threats Mitigated:**
*   **Host Network Exposure (High Severity):**
*   **Network Attacks (High Severity):**

**Impact:**
*   **Host Network Exposure:** Risk reduced.
*   **Network Attacks:** Risk reduced.

**Currently Implemented:**
*   Informal avoidance of `--network=host`.

**Missing Implementation:**
*   Formal policy and automated checks using `podman inspect` are not in place.

## Mitigation Strategy: [Resource Limits (cgroups)](./mitigation_strategies/resource_limits__cgroups_.md)

**Mitigation Strategy:** Set Resource Limits

**Description:**
1.  **Podman Flags:** Use Podman's resource limit flags directly with `podman run` (and related commands):
    *   `--cpu-shares`
    *   `--memory`
    *   `--memory-swap`
    *   `--blkio-weight`
    *   `--pids-limit` (important for preventing fork bombs)
2.  **Verification (with Podman):** Use `podman inspect` to verify the applied resource limits (e.g., `Memory`, `CpuShares`).

**Threats Mitigated:**
*   **Denial of Service (DoS) (Medium Severity):**
*   **Resource Exhaustion (Medium Severity):**

**Impact:**
*   **Denial of Service (DoS):** Risk reduced.
*   **Resource Exhaustion:** Risk reduced.

**Currently Implemented:**
*   Basic memory limits are set in some `docker-compose.yml` files.

**Missing Implementation:**
*   Consistent use of all relevant resource limit flags is not in place.
*   Verification using `podman inspect` is not automated.

## Mitigation Strategy: [Podman Events and Auditing](./mitigation_strategies/podman_events_and_auditing.md)

**Mitigation Strategy:** Monitor Podman Events

**Description:**
1.  **`podman events`:** Use the `podman events` command (potentially with `--filter` options) to monitor container lifecycle events. This is the *direct* Podman interaction.  This can be integrated into scripts for monitoring.
2. **`podman logs`**: Use `podman logs` to check logs of the container.

**Threats Mitigated:**
*   **Intrusion Detection (Medium Severity):**
*   **Incident Response (Medium Severity):**

**Impact:**
*   **Intrusion Detection:** Improves detection.
*   **Incident Response:** Improves response.

**Currently Implemented:**
*   Not implemented.

**Missing Implementation:**
*   `podman events` is not used for monitoring.

## Mitigation Strategy: [Container Introspection](./mitigation_strategies/container_introspection.md)

**Mitigation Strategy:** Regularly Inspect Running Containers

**Description:**
1.  **`podman inspect`:** Use `podman inspect` as the *primary* tool for examining container details. This is the core Podman-direct action.  The output can be parsed (e.g., with `jq`) to check specific configuration values.
2.  **`podman top`:** Use `podman top <container_id>` to view the processes running *inside* a container. This is a direct Podman command for process inspection.
3.  **`podman stats`:** Use `podman stats` to monitor resource usage of running containers.

**Threats Mitigated:**
*   **Compromised Containers (Medium Severity):**
*   **Malware Execution (Medium Severity):**

**Impact:**
*   **Compromised Containers:** Improves detection.
*   **Malware Execution:** Improves detection.

**Currently Implemented:**
*   Manual inspections are performed occasionally.

**Missing Implementation:**
*   Regular, automated use of `podman inspect`, `podman top`, and `podman stats` is not in place.

