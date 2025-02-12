# Mitigation Strategies Analysis for reactivex/rxandroid

## Mitigation Strategy: [Robust Subscription Management with CompositeDisposable](./mitigation_strategies/robust_subscription_management_with_compositedisposable.md)

**Description:**
1.  **Initialization:** In each Activity or Fragment that uses RxJava subscriptions, declare a `CompositeDisposable` instance variable: `private val compositeDisposable = CompositeDisposable()`.
2.  **Subscription Handling:** Whenever you subscribe to an `Observable` or `Flowable` (using `.subscribe()`), immediately add the returned `Disposable` to the `compositeDisposable`: `compositeDisposable.add(myObservable.subscribe(...))`.
3.  **Disposal:** In the `onDestroy()` method of your Activity or Fragment (or `onStop()` if appropriate), call `compositeDisposable.clear()`.  This unsubscribes from all active subscriptions, preventing leaks.  If you might resubscribe in `onStart()`, use `clear()`; otherwise, use `dispose()` to prevent further additions.
4. **Consistency:** Ensure this pattern is consistently applied across *all* Activities and Fragments that use RxJava.

**List of Threats Mitigated:**
*   **Resource Leaks (Memory, CPU, Battery, Network):**  Severity: High.  Unintentional background operations can consume significant resources.
*   **Data Inconsistency:** Severity: Medium to High.  Background operations modifying shared state after UI destruction.
*   **Unintentional Denial of Service (DoS):** Severity: Medium.  Resource exhaustion making the application unusable.

**Impact:**
*   **Resource Leaks:** Risk significantly reduced (close to eliminated if implemented consistently).
*   **Data Inconsistency:** Risk significantly reduced.
*   **Unintentional DoS:** Risk significantly reduced.

**Currently Implemented:**
*   *Example:* `MainActivity.kt`, `MyFragment.kt` (using `compositeDisposable.clear()` in `onDestroy()`).
*   *(Fill in with your project details.)*

**Missing Implementation:**
*   *Example:* `NetworkDataFragment.kt` (using individual `Disposable` variables).
*   *(Fill in with your project details.)*

## Mitigation Strategy: [Correct Threading with subscribeOn and observeOn](./mitigation_strategies/correct_threading_with_subscribeon_and_observeon.md)

**Description:**
1.  **Background Operations:** Use `subscribeOn()` to specify the thread for the *source* Observable's work. For network/database/heavy computations, use `Schedulers.io()` or `Schedulers.computation()`.  Example: `myNetworkObservable.subscribeOn(Schedulers.io())`.
2.  **UI Updates:** Use `observeOn(AndroidSchedulers.mainThread())` to switch to the main thread *only* for UI updates, *after* background work. Example: `.observeOn(AndroidSchedulers.mainThread())`.
3.  **Avoid Long Operations on Main Thread:** Code after `observeOn(AndroidSchedulers.mainThread())` must be fast and non-blocking. Chain another `subscribeOn()` if needed.
4. **Granularity:** Break down large tasks using operators like `flatMap`, `concatMap`, or `switchMap`.

**List of Threats Mitigated:**
*   **UI Freezes/ANRs (Application Not Responding):** Severity: High. Blocking the main thread.
*   **CalledFromWrongThreadException:** Severity: High.  Updating UI from a background thread.

**Impact:**
*   **UI Freezes/ANRs:** Risk significantly reduced.
*   **CalledFromWrongThreadException:** Risk eliminated.

**Currently Implemented:**
*   *Example:* `UserRepository.kt` (correct `subscribeOn` and `observeOn` usage).
*   *(Fill in with your project details.)*

**Missing Implementation:**
*   *Example:* `ImageProcessingService.kt` (image manipulation on the main thread).
*   *(Fill in with your project details.)*

## Mitigation Strategy: [Comprehensive Error Handling](./mitigation_strategies/comprehensive_error_handling.md)

**Description:**
1.  **onError Handler:** In *every* `subscribe()` call, provide an `onError` handler (lambda or method reference) to handle errors. At minimum, log the error.
2.  **User Feedback:**  In the `onError` handler, consider displaying an error message to the user.
3.  **Retry Logic:** For transient errors, use `retry()` or `retryWhen()` for automatic retries. `retryWhen` allows complex strategies (e.g., exponential backoff).
4.  **Error Recovery:** Use `onErrorResumeNext` to switch to a different Observable, or `onErrorReturn` to emit a default value.
5.  **Global Error Handler (Limited Use):**  Set a global handler with `RxJavaPlugins.setErrorHandler()`. Use this *only* for logging unhandled errors and a generic error message. Avoid complex logic.

**List of Threats Mitigated:**
*   **Unhandled Exceptions (Crashes):** Severity: High. Unhandled errors crash the app.
*   **Unexpected Application State:** Severity: Medium. Errors can lead to inconsistency.
*   **Poor User Experience:** Severity: Medium. No information about errors.

**Impact:**
*   **Unhandled Exceptions:** Risk significantly reduced.
*   **Unexpected Application State:** Risk reduced.
*   **Poor User Experience:** Risk reduced.

**Currently Implemented:**
*   *Example:* `NetworkService.kt` (using `onError`, `retry(3)`).
*   *(Fill in with your project details.)*

**Missing Implementation:**
*   *Example:* `DatabaseHelper.kt` (missing `onError` handlers).
*   *(Fill in with your project details.)*

## Mitigation Strategy: [Backpressure Handling (If Applicable)](./mitigation_strategies/backpressure_handling__if_applicable_.md)

**Description:**
1.  **Identify Potential Backpressure:** Check if any Observables emit items faster than consumption. Likely with fast data sources (sensors, network streams).
2.  **Use Flowable:** If backpressure is a concern, use `Flowable` instead of `Observable`. `Flowable` is designed for this.
3.  **Choose a Backpressure Strategy:** When creating a `Flowable`, specify a `BackpressureStrategy`:
    *   `BackpressureStrategy.BUFFER`: Buffers items (risk of `OutOfMemoryError`).
    *   `BackpressureStrategy.DROP`: Drops *oldest* items.
    *   `BackpressureStrategy.LATEST`: Drops all but the *most recent* item.
    *   `BackpressureStrategy.ERROR`: Signals `MissingBackpressureException`.
    *   `BackpressureStrategy.MISSING`: No strategy; relies on downstream operators.
4.  **Operators:** Use `onBackpressureBuffer`, `onBackpressureDrop`, or `onBackpressureLatest` on an existing `Observable`.
5.  **Windowing/Buffering:** Consider `window`, `buffer`, or `sample` to reduce emission rate.

**List of Threats Mitigated:**
*   **MissingBackpressureException:** Severity: High. Crashes the application.
*   **OutOfMemoryError:** Severity: High. Unbounded buffering.
*   **Data Loss:** Severity: Medium (depending on strategy). `DROP` and `LATEST` lose data.

**Impact:**
*   **MissingBackpressureException:** Risk eliminated.
*   **OutOfMemoryError:** Risk significantly reduced.
*   **Data Loss:** Risk managed (but potentially present).

**Currently Implemented:**
*   *Example:* `SensorDataManager.kt` (using `Flowable`, `BackpressureStrategy.LATEST`).
*   *(Fill in with your project details.)*

**Missing Implementation:**
*   *Example:* `NetworkStreamProcessor.kt` (using `Observable` without backpressure handling).
*   *(Fill in with your project details.)*

