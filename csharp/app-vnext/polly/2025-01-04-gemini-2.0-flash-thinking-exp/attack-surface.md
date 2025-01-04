# Attack Surface Analysis for app-vnext/polly

## Attack Surface: [Insecure Policy Configuration](./attack_surfaces/insecure_policy_configuration.md)

**Description:**  Polly's behavior is governed by configurable policies (retry, circuit breaker, etc.). Insecure or overly permissive configurations can be exploited.

**How Polly Contributes:**  Polly's flexibility allows for a wide range of configurations. Incorrectly configured policies can create new attack vectors.

**Example:**  A retry policy is configured with an extremely high retry count and no backoff strategy. An attacker can trigger failures in a downstream service, causing the application to repeatedly retry, leading to resource exhaustion and denial of service on the application server.

**Impact:**  Denial of service, resource exhaustion, potential for amplified attacks against downstream services.

**Risk Severity:** High.

**Mitigation Strategies:**
* Implement least privilege principles for configuration access and modification.
* Thoroughly review and test all Polly policy configurations before deployment.
* Set reasonable limits for retry attempts, timeouts, and circuit breaker thresholds.
* Consider using backoff strategies in retry policies to mitigate resource exhaustion.

## Attack Surface: [Exploitation of Fallback Policies](./attack_surfaces/exploitation_of_fallback_policies.md)

**Description:**  If a fallback policy involves executing code or accessing resources, an attacker might try to trigger the fallback intentionally to exploit vulnerabilities in the fallback logic.

**How Polly Contributes:**  Polly's fallback policies define actions to take when failures occur. If these actions are not secure, they become an attack vector.

**Example:**  A fallback policy logs detailed error messages including sensitive information. An attacker can trigger failures to force the application to log this sensitive data, which they can then access. Another example is a fallback policy that returns a default value that bypasses security checks.

**Impact:**  Information disclosure, bypassing security controls, potential for further exploitation depending on the fallback logic.

**Risk Severity:** High (depending on the fallback implementation).

**Mitigation Strategies:**
* Avoid executing complex or untrusted code in fallback policies.
* Ensure fallback policies do not leak sensitive information.
* Carefully review and test fallback logic for potential vulnerabilities.
* Implement strict authorization checks within fallback handlers if they access sensitive resources.

