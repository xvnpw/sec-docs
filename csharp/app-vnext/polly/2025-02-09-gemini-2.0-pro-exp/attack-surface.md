# Attack Surface Analysis for app-vnext/polly

## Attack Surface: [Retry Storm Amplification](./attack_surfaces/retry_storm_amplification.md)

*   **Description:** Attackers exploit overly aggressive retry policies to amplify a small number of malicious requests into a much larger load on downstream services, causing a denial-of-service (DoS).
*   **How Polly Contributes:** Polly's retry policies, if misconfigured, are the *direct mechanism* for this amplification.  Without Polly, this specific amplification attack is not possible in the same way.
*   **Example:** An attacker sends a request that consistently fails. Polly, configured to retry 100 times with minimal delay, floods the backend service with 100 requests for each attacker request.
*   **Impact:** Downstream service overload, unavailability, potential cascading failures.
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   Implement a reasonable maximum number of retries (e.g., 3-5).
    *   Use exponential backoff with jitter: Increase the delay between retries exponentially and add random "jitter" to prevent synchronized retries.  Example: `TimeSpan.FromSeconds(Math.Pow(2, retryAttempt)) + TimeSpan.FromMilliseconds(_random.Next(0, 100))`.
    *   Monitor retry rates and trigger alerts for unusually high activity.
    *   Combine retries with a Circuit Breaker (see below) for sustained failures.

## Attack Surface: [Resource Exhaustion via Timeouts](./attack_surfaces/resource_exhaustion_via_timeouts.md)

*   **Description:** Attackers exploit poorly configured timeout policies to consume application resources (threads, connections) leading to denial-of-service.
*   **How Polly Contributes:** Polly's timeout policies, if too long or absent, *directly enable* this attack by allowing requests to consume resources for extended periods.  The `TimeoutPolicy` is the specific Polly component involved.
*   **Example:** An attacker sends a request designed to take a very long time to process.  With no timeout (or a very long one) configured in Polly, the application thread handling that request is blocked, reducing the application's capacity.
*   **Impact:** Application slowdown, unresponsiveness, potential crashes.
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   Always set a reasonable timeout using Polly's `TimeoutPolicy`.  Base the timeout duration on expected response times plus a buffer.
    *   Use `TimeoutStrategy.Pessimistic` to ensure the calling thread is interrupted when the timeout expires.
    *   Monitor application resource usage (thread pool, connection pool) and set alerts.

## Attack Surface: [Circuit Breaker Manipulation (Forced Opening)](./attack_surfaces/circuit_breaker_manipulation__forced_opening_.md)

*   **Description:** Attackers intentionally trigger failures to force a Polly Circuit Breaker into an open state, causing a denial-of-service by preventing legitimate requests.
*   **How Polly Contributes:** The Circuit Breaker is a *core Polly feature*, and its state is directly manipulated by the attacker. This attack is specific to the use of Polly's `CircuitBreakerPolicy`.
*   **Example:** An attacker sends a series of requests designed to fail, exceeding the Circuit Breaker's failure threshold (configured within Polly) and causing it to open.
*   **Impact:** Downstream service effectively becomes unavailable to the application.
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   Carefully configure the Circuit Breaker's thresholds (failure rate, duration of break) within the Polly policy. Avoid overly sensitive settings.
    *   Monitor Circuit Breaker state transitions and investigate unexpected openings.
    *   Implement rate limiting *before* the Circuit Breaker (this is external to Polly but mitigates the attack on Polly).
    *   Use a "half-open" state (a Polly feature) to allow limited requests to test the downstream service.

## Attack Surface: [Policy Ordering Issues](./attack_surfaces/policy_ordering_issues.md)

*   **Description:** Incorrect ordering of wrapped Polly policies leads to unexpected behavior and bypasses intended protections.
*   **How Polly Contributes:** Polly *allows and requires* policies to be chained, and the order is a direct configuration choice within Polly. This is inherent to Polly's design.
*   **Example:** Placing a timeout *inside* a retry policy means the timeout applies to *each retry attempt*, not the overall operation. This could allow an operation to take much longer than intended, leading to resource exhaustion.
*   **Impact:** Ineffective resilience, potential for resource exhaustion or other unintended consequences.
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   Thoroughly understand the interaction between different Polly policies.
    *   Carefully design the policy wrapping order to achieve the desired behavior. Generally, wrap from *outermost* to *innermost*: Timeout > Circuit Breaker > Retry > Bulkhead > Fallback. This is a Polly-specific configuration task.
    *   Extensive testing of the combined policy behavior is crucial.
    *   Document the policy wrapping strategy clearly.

