# Threat Model Analysis for app-vnext/polly

## Threat: [Excessive Retry Exploitation](./threats/excessive_retry_exploitation.md)

**Description:** An attacker might intentionally cause failures in a dependent service to force the application to execute a large number of retries defined by a `RetryPolicy`. This could exhaust the application's resources (CPU, memory, network connections) or overwhelm the failing service with repeated requests even after it's clear it's unavailable.

**Impact:** Denial of Service (DoS) on the application or the dependent service, performance degradation, increased latency for legitimate requests.

**Affected Polly Component:** `RetryPolicy` module, specifically the configuration of `retryCount` and `sleepDuration`.

**Mitigation Strategies:**
* Implement circuit breakers in conjunction with retry policies to stop retries after a certain number of consecutive failures.
* Configure retry policies with reasonable limits on the number of retries and appropriate delays between retries (consider exponential backoff).
* Implement monitoring and alerting for excessive retry attempts to detect potential attacks.
* Consider using jitter in retry delays to avoid synchronized retry storms.

## Threat: [Fallback Policy Manipulation](./threats/fallback_policy_manipulation.md)

**Description:** If the fallback action defined in a `FallbackPolicy` involves executing code or accessing resources, an attacker might try to influence the conditions that trigger the fallback to execute malicious code or access unauthorized resources. This could involve manipulating input data or exploiting vulnerabilities in the fallback implementation itself.

**Impact:** Execution of malicious code, unauthorized access to resources, data corruption, information disclosure.

**Affected Polly Component:** `FallbackPolicy` module, specifically the `fallbackAction` delegate or function.

**Mitigation Strategies:**
* Ensure the fallback action is secure and does not introduce new vulnerabilities.
* Avoid performing complex or potentially risky operations within the fallback action.
* Sanitize any input data used within the fallback action.
* Treat the fallback action as a critical component and apply the same security scrutiny as other parts of the application.

## Threat: [Configuration Injection/Tampering](./threats/configuration_injectiontampering.md)

**Description:** An attacker might attempt to inject malicious values or tamper with the configuration of Polly policies (retry counts, timeouts, circuit breaker thresholds, etc.) if the configuration mechanism is not properly secured. This could lead to unexpected behavior, denial of service, or other security vulnerabilities.

**Impact:** Application instability, denial of service, bypassing intended resilience mechanisms, potential for further exploitation depending on the manipulated configuration.

**Affected Polly Component:** All Polly policy modules (`RetryPolicy`, `CircuitBreaker`, `TimeoutPolicy`, `Bulkhead`, `FallbackPolicy`), and the configuration mechanism used to define these policies.

**Mitigation Strategies:**
* Store Polly configurations securely and restrict access to configuration files or services.
* Avoid hardcoding sensitive configuration values directly in the code.
* Use environment variables or dedicated configuration management tools.
* Implement validation and sanitization of configuration values before they are used by Polly.
* Ensure that the configuration mechanism itself is not vulnerable to injection attacks.

