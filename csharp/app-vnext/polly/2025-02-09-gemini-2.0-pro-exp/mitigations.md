# Mitigation Strategies Analysis for app-vnext/polly

## Mitigation Strategy: [Bounded Retries with Exponential Backoff and Jitter (using Polly's `RetryPolicy`)](./mitigation_strategies/bounded_retries_with_exponential_backoff_and_jitter__using_polly's__retrypolicy__.md)

**Description:**
1.  **Identify Retry Points:** Locate all instances where Polly's `RetryPolicy` or `WaitAndRetryPolicy` is used.
2.  **Set Maximum Retries:** Ensure `RetryForever()` is *never* used. Replace with `Retry(n)` or `WaitAndRetryAsync(n, ...)` where `n` is a small, finite number (e.g., 3-5).
3.  **Implement Exponential Backoff:** Use `WaitAndRetryAsync` with a `sleepDurationProvider` delegate.  Calculate delay: `TimeSpan.FromSeconds(Math.Pow(2, attempt))`.
4.  **Add Jitter:** Within `sleepDurationProvider`, add random component: `+ TimeSpan.FromMilliseconds(_random.Next(0, 100))`. Use a thread-safe random number generator.
5.  **Test:** Verify retry logic (number of retries, delays, jitter) with unit/integration tests.

**Threats Mitigated:**
*   **DoS Amplification (High Severity):** Polly won't flood services with retries.
*   **Resource Exhaustion (Medium Severity):** Limits resources used by retries.
*   **Covert Channel (Low Severity):** Jitter reduces timing predictability.

**Impact:**
*   **DoS Amplification:** Significantly reduced; retries are strictly bounded.
*   **Resource Exhaustion:** Reduced by limiting retry duration/frequency.
*   **Covert Channel:** Moderate reduction due to randomness.

**Currently Implemented:**
*   `OrderService.cs`: `WaitAndRetryAsync` with exponential backoff and jitter for `PaymentGateway` calls.
*   `ProductCatalogClient.cs`: `Retry(3)` for fetching product details.

**Missing Implementation:**
*   `NotificationService.cs`: Uses `RetryForever()`. Needs bounded retry, backoff, and jitter.
*   `UserAuthenticationService.cs`: `Retry(2)` without delay/jitter. Needs `WaitAndRetryAsync`.

## Mitigation Strategy: [Fallback with Timeouts (using Polly's `FallbackPolicy` and `TimeoutPolicy`)](./mitigation_strategies/fallback_with_timeouts__using_polly's__fallbackpolicy__and__timeoutpolicy__.md)

**Description:**
1.  **Identify Fallback Policies:** Locate `FallbackPolicy` or `FallbackAsync` instances.
2.  **Analyze Fallback Actions:** Ensure the `fallbackAction` delegate is simple and efficient.
3.  **Minimize Resource Consumption:** Avoid complex logic/queries. Prefer cached data (validated) or default values.
4.  **Implement Timeouts:** Wrap `fallbackAction` with a `TimeoutPolicy`. Use `TimeoutStrategy.Pessimistic` (if uninterruptible) or `TimeoutStrategy.Optimistic`.  Example:
    ```csharp
    Policy.TimeoutAsync(TimeSpan.FromSeconds(2), TimeoutStrategy.Pessimistic)
          .WrapAsync(Policy.Handle<Exception>().FallbackAsync(...));
    ```
5.  **Test:** Verify fallback actions are fast, resource-efficient, and respect timeouts.

**Threats Mitigated:**
*   **Resource Exhaustion (Medium Severity):** Fallbacks don't consume excessive resources.

**Impact:**
*   **Resource Exhaustion:** Significantly reduced; fallbacks are lightweight and time-limited.

**Currently Implemented:**
*   `ProductService.cs`: Fallback returns cached product list (short TTL) with a 2-second timeout.
*   `RecommendationService.cs`: Returns default recommendations with a 1-second timeout.

**Missing Implementation:**
*   `OrderProcessingService.cs`: Fallback sends email (slow/failable). Needs timeout, simpler fallback.
*   `AnalyticsService.cs`: Fallback performs complex calculation. Simplify or use cached value.

## Mitigation Strategy: [Policy Ordering (using Polly's `PolicyWrap`)](./mitigation_strategies/policy_ordering__using_polly's__policywrap__.md)

**Description:**
1.  **Identify Policy Wraps:** Locate all `PolicyWrap` instances.
2.  **Analyze Policy Order:** Security policies (authentication, authorization) *must* be *inside* resilience policies (retry, circuit breaker, fallback).
3.  **Correct Ordering:** Refactor if incorrect. Example: `authenticationPolicy.Wrap(retryPolicy.Wrap(circuitBreakerPolicy))`. 
4.  **Document Rationale:** Explain why security policies are inside.
5.  **Test:** Verify security checks happen *before* resilience logic, even on failures.

**Threats Mitigated:**
*   **Bypassing Security Controls (High Severity):** Resilience doesn't bypass auth checks.

**Impact:**
*   **Bypassing Security Controls:** Eliminates this specific bypass risk.

**Currently Implemented:**
*   `ApiService.cs`: Correctly wraps auth policies inside retry/circuit breaker.
*   `SecureDataClient.cs`: Data access policies applied before retries.

**Missing Implementation:**
*   `LegacyIntegrationService.cs`: Retry *before* authentication. Needs correction.
*   `ExternalServiceClient.cs`: Policy order unclear; review and document.

## Mitigation Strategy: [Circuit Breaker Integration with Retries (using Polly's `CircuitBreakerPolicy` and `RetryPolicy`)](./mitigation_strategies/circuit_breaker_integration_with_retries__using_polly's__circuitbreakerpolicy__and__retrypolicy__.md)

**Description:**
1. **Identify Retry Policies:** Locate instances where `RetryPolicy` is used, especially for external dependencies.
2. **Combine with Circuit Breaker:** Wrap the `RetryPolicy` with a `CircuitBreakerPolicy`. This prevents repeated attempts to a failing service after a certain threshold.
   ```csharp
   Policy
       .Handle<Exception>()
       .CircuitBreakerAsync(
           exceptionsAllowedBeforeBreaking: 3,
           durationOfBreak: TimeSpan.FromMinutes(1)
       )
       .WrapAsync(retryPolicy); // retryPolicy defined earlier
   ```
3. **Configure Circuit Breaker:**
    *   `exceptionsAllowedBeforeBreaking`: Number of failures before the circuit opens.
    *   `durationOfBreak`: How long the circuit stays open before transitioning to half-open.
4. **Test:** Simulate sustained failures and verify the circuit breaker opens and closes as expected.

**Threats Mitigated:**
*   **DoS Amplification (High Severity):** Prevents continued retries to a failing service, reducing load.
*   **Resource Exhaustion (Medium Severity):** Avoids wasting resources on repeated failed attempts.

**Impact:**
*   **DoS Amplification:** Significantly reduced by stopping requests to a failing service.
*   **Resource Exhaustion:** Reduced by preventing resource consumption on known-to-fail operations.

**Currently Implemented:**
*   `ExternalPaymentService.cs`: Combines `RetryPolicy` and `CircuitBreakerPolicy` for calls to a payment gateway.
*   `DatabaseClient.cs`: Uses a circuit breaker to protect against database connection failures.

**Missing Implementation:**
*   `ThirdPartySearchService.cs`: Only uses a `RetryPolicy`. Should be combined with a `CircuitBreakerPolicy`.
*   `MessageQueueClient.cs`: No circuit breaker; repeated failures could overwhelm the message queue.

