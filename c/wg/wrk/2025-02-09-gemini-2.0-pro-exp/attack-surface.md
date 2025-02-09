# Attack Surface Analysis for wg/wrk

## Attack Surface: [Resource Exhaustion (Denial of Service) - Due to `wrk` Misconfiguration/Misuse](./attack_surfaces/resource_exhaustion__denial_of_service__-_due_to__wrk__misconfigurationmisuse.md)

*   **Description:** Overwhelming the target system's resources due to improperly configured or misused `wrk` commands, leading to service degradation or unavailability. This is `wrk` *causing* the DoS, not just testing for it.
*   **How `wrk` Contributes:** `wrk` is the *direct* tool generating the excessive load. The risk stems from how it's used, not an inherent flaw in the target.
*   **Example:** Running `wrk` with excessively high `-t` (threads) and `-c` (connections) values without proper monitoring or a kill switch, causing the target system to crash. `wrk -t100 -c10000 -d600s https://example.com/` (without proper precautions).
*   **Impact:** Service unavailability, data loss (if transactions are interrupted), potential damage to hardware (in extreme cases).
*   **Risk Severity:** Critical
*   **Mitigation Strategies:**
    *   **Careful Configuration:** Start with *low* values for `-t`, `-c`, and `-d`, and gradually increase them *only* while closely monitoring the target system.
    *   **Resource Monitoring:** Continuously monitor the target system's resources (CPU, memory, network, application-specific metrics).
    *   **Kill Switch:** Have a readily available method to *immediately* stop the `wrk` process.
    *   **Staged Testing:** Test in a staging environment *before* production.
    *   **Network Awareness:** Ensure the network between `wrk` and the target has sufficient capacity.

## Attack Surface: [Malicious Lua Script Execution](./attack_surfaces/malicious_lua_script_execution.md)

*   **Description:**  Running a malicious Lua script with `wrk`'s `-s` option, leading to arbitrary code execution *on the machine running `wrk`*.
*   **How `wrk` Contributes:** The `-s` option of `wrk` *directly* enables the execution of arbitrary Lua code. This is the core of the risk.
*   **Example:**  Downloading and running a Lua script from an untrusted source that contains malicious code. `wrk -s ./malicious.lua ...`
*   **Impact:**  Compromise of the machine running `wrk`, data theft, malware installation, potential lateral movement.
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   **Never Run Untrusted Scripts:**  *Only* run Lua scripts from trusted, verified sources.
    *   **Code Review:**  *Thoroughly* review and audit *any* custom Lua script before execution.
    *   **Sandboxing:** Run `wrk` in a sandboxed environment (container, VM) to limit the impact of a compromised script.
    *   **Principle of Least Privilege:** Run `wrk` as a non-privileged user.

## Attack Surface: [Compromised `wrk` Binary](./attack_surfaces/compromised__wrk__binary.md)

*   **Description:** Using a `wrk` binary that has been tampered with, potentially leading to malicious behavior *of the `wrk` process itself*.
*   **How `wrk` Contributes:** The compromised binary *is* `wrk`, so the risk is entirely within the tool itself.
*   **Example:** Downloading `wrk` from an unofficial, compromised source.
*   **Impact:** Compromise of the machine running `wrk`; the attacker could control the load generation or execute arbitrary code.
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   **Trusted Source:** Obtain `wrk` *only* from the official GitHub repository.
    *   **Checksum Verification:** Verify the binary's integrity using checksums (if provided).
    *   **Build from Source:** Consider building `wrk` from source after auditing the code.

