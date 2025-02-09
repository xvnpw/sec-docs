# Mitigation Strategies Analysis for dotnet/reactive

## Mitigation Strategy: [Backpressure Handling (Rx.NET Operators)](./mitigation_strategies/backpressure_handling__rx_net_operators_.md)

**Description:**
1.  **Identify High-Volume Observables:** Analyze data flow to pinpoint Observables producing high-rate or bursty data.
2.  **Choose Appropriate Operators:** Select Rx.NET operators for backpressure:
    *   `Buffer(count)`: Batches items into fixed-size groups.
    *   `Buffer(timeSpan)`: Batches items within a time window.
    *   `Sample(timeSpan)`: Emits the *last* item within a time window.
    *   `Throttle(timeSpan)`: Emits an item, then ignores subsequent items for a duration.
    *   `Debounce(timeSpan)`: Emits an item after a period of silence.
    *   `Window(count/timeSpan)`: Emits *Observables* of buffered items.
3.  **Strategic Operator Placement:** Insert operators *before* computationally expensive or resource-limited operations.
4.  **Thorough Testing:** Create tests simulating high-volume scenarios to verify backpressure.

**Threats Mitigated:**
*   **Denial of Service (DoS) via Uncontrolled Observables:** (Severity: High)
*   **Resource Exhaustion (CPU, Memory, Threads):** (Severity: High)
*   **Application Unresponsiveness:** (Severity: Medium)

**Impact:**
*   **DoS:** Risk significantly reduced (High impact).
*   **Resource Exhaustion:** Risk significantly reduced (High impact).
*   **Application Unresponsiveness:** Risk moderately reduced (Medium impact).

**Currently Implemented:** Partially. `Debounce` on search input (`SearchService.cs`). `Throttle` on sensor data (`SensorDataProcessor.cs`).

**Missing Implementation:** Missing on stock price feed (`StockPriceService.cs`) and user activity log (`UserActivityLogger.cs`).

## Mitigation Strategy: [Subscription Timeouts (Rx.NET `Timeout` Operator)](./mitigation_strategies/subscription_timeouts__rx_net__timeout__operator_.md)

**Description:**
1.  **Identify Potentially Hanging Observables:**  Find Observables that might not complete or emit values (e.g., network requests, long-running operations).
2.  **Apply `Timeout` Operator:**  Use the `Timeout(TimeSpan)` operator on these Observables.  Set a reasonable timeout value based on expected behavior.
3.  **Handle `TimeoutException`:**  Use a `Catch` block to handle the `TimeoutException` that is thrown when the timeout occurs.  Implement appropriate error handling (retry, log, notify user).

**Threats Mitigated:**
*   **Hanging Subscriptions:** (Severity: Medium) - Prevents indefinite blocking.
*   **Resource Exhaustion (Threads):** (Severity: Medium) - Releases resources held by hanging subscriptions.

**Impact:**
*   **Hanging Subscriptions:** Risk significantly reduced (High impact).
*   **Resource Exhaustion:** Risk moderately reduced (Medium impact).

**Currently Implemented:** Implemented for network requests (`NetworkService.cs`).

**Missing Implementation:**  Not consistently applied to other potentially long-running operations.

## Mitigation Strategy: [Error Handling with Rx.NET Operators](./mitigation_strategies/error_handling_with_rx_net_operators.md)

**Description:**
1.  **`Catch` for Specific Exceptions:** Use `Catch` to handle specific exceptions within the Observable chain. Avoid catching generic `Exception`.
2.  **`Retry` for Transient Errors:** Use `Retry` for automatic retries on transient errors (e.g., network issues).  Consider a backoff strategy.
3.  **`OnErrorResumeNext` for Fallbacks:** Use `OnErrorResumeNext` to switch to a different Observable sequence on error, providing a fallback.
4. **Test Error Scenarios:** Create unit tests that specifically test error handling within your Observable chains.

**Threats Mitigated:**
*   **Unhandled Exceptions:** (Severity: High)
*   **Application Crashes:** (Severity: High)
*   **Inconsistent State:** (Severity: Medium)
*   **Masked Errors:** (Severity: Low)

**Impact:**
*   **Unhandled Exceptions:** Risk significantly reduced (High impact).
*   **Application Crashes:** Risk significantly reduced (High impact).
*   **Inconsistent State:** Risk moderately reduced (Medium impact).
*   **Masked Errors:** Risk significantly reduced (High impact).

**Currently Implemented:** Partially. `Catch` used in some places.

**Missing Implementation:** `Retry` and `OnErrorResumeNext` not widely used. Comprehensive review needed. Error handling not consistently tested.

## Mitigation Strategy: [Safe Replay Subject Usage (Rx.NET `ReplaySubject` Parameters)](./mitigation_strategies/safe_replay_subject_usage__rx_net__replaysubject__parameters_.md)

**Description:**
1.  **Assess Necessity:** Determine if `ReplaySubject` or `BehaviorSubject` is truly required.
2.  **Limit Buffer Size:** Use the `ReplaySubject` constructor with `bufferSize` to limit cached values.
3.  **Time-Based Expiration:** Use the `ReplaySubject` constructor with `window` (a `TimeSpan`) for time-based caching.
4.  **Avoid Sensitive Data:** *Never* store sensitive data directly in a `ReplaySubject` or `BehaviorSubject`.
5.  **Clear on Invalidation:** Explicitly clear the `ReplaySubject` (using `OnCompleted` or a new instance) when data is invalid.

**Threats Mitigated:**
*   **Replay Attacks:** (Severity: High)
*   **Information Disclosure:** (Severity: High)
*   **Stale Data Issues:** (Severity: Medium)

**Impact:**
*   **Replay Attacks:** Risk significantly reduced (High impact).
*   **Information Disclosure:** Risk significantly reduced (High impact).
*   **Stale Data Issues:** Risk significantly reduced (High impact).

**Currently Implemented:** Partially. `ReplaySubject` in user profile caching (`UserProfileService.cs`) has limited buffer size, but no time-based expiration.

**Missing Implementation:** No time-based expiration in `UserProfileService.cs`. No explicit clearing. Review all `ReplaySubject`/`BehaviorSubject` uses.

## Mitigation Strategy: [Using `TakeUntil` for unsubscription](./mitigation_strategies/using__takeuntil__for_unsubscription.md)

**Description:**
1. **Identify trigger:** Find observable that will emit value when unsubscription should happen.
2. **Apply `TakeUntil` Operator:** Use the `TakeUntil(IObservable<T>)` operator on main Observable. Pass trigger observable as parameter.
3. **Test unsubscription:** Create unit tests that specifically test unsubscription logic.

**Threats Mitigated:**
*   **Memory Leaks:** (Severity: Medium) - Prevents subscriptions from lingering indefinitely and consuming memory.
*   **Resource Exhaustion (Threads):** (Severity: Medium) - Reduces the number of threads potentially blocked by long-running subscriptions.

**Impact:**
*   **Memory Leaks:** Risk significantly reduced (High impact).
*   **Resource Exhaustion:** Risk moderately reduced (Medium impact).

**Currently Implemented:** Not implemented.

**Missing Implementation:**  Not consistently used for component lifecycle management.

