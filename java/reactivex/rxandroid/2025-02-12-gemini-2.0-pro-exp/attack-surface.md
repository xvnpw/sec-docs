# Attack Surface Analysis for reactivex/rxandroid

## Attack Surface: [Memory Leaks due to Undisposed Subscriptions](./attack_surfaces/memory_leaks_due_to_undisposed_subscriptions.md)

*   **Description:**  Failure to dispose of `Observable` subscriptions (using `Disposable.dispose()`) leads to objects being held in memory indefinitely, preventing garbage collection and eventually causing `OutOfMemoryError` crashes.
*   **How RxAndroid Contributes:** RxAndroid facilitates the creation of `Observable` streams (often tied to Android components like Activities and Fragments).  If developers don't manage the lifecycle of these RxJava/RxAndroid streams correctly, leaks are highly likely.  This is a *direct* consequence of using RxAndroid's reactive programming model.
*   **Example:** An `Activity` subscribes to an `Observable` (e.g., for network updates) in `onCreate()` but doesn't dispose of the subscription in `onDestroy()`.  Each time the `Activity` is recreated, a new subscription is created, but the old one remains, holding a reference to the previous `Activity` instance, preventing garbage collection.
*   **Impact:** Application crash (DoS), degraded performance, potential instability.
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   **Developers:** Always dispose of `Disposable` objects when they are no longer needed, typically in lifecycle methods like `onDestroy()`, `onPause()`, or `onStop()`. Use `CompositeDisposable` to manage multiple disposables.  Utilize RxLifecycle or Android Architecture Components (ViewModel) with LiveData/Flow to automate subscription management based on component lifecycles.  Use memory profiling tools (Android Profiler) to detect leaks during development.

## Attack Surface: [UI Freezes/Deadlocks from Improper Threading](./attack_surfaces/ui_freezesdeadlocks_from_improper_threading.md)

*   **Description:** Performing long-running operations on the main thread, blocking the UI and making the application unresponsive.
*   **How RxAndroid Contributes:** RxAndroid provides `Schedulers` (specifically `AndroidSchedulers.mainThread()`) for thread management.  Incorrect use of `subscribeOn()` and `observeOn()`, or failing to use them at all with RxAndroid's `Schedulers`, *directly* leads to operations being executed on the wrong thread (often unintentionally on the main thread).
*   **Example:** A network request is initiated within an Rx stream using RxAndroid.  If `subscribeOn(Schedulers.io())` is omitted, and the result is observed using `observeOn(AndroidSchedulers.mainThread())`, the network request (a blocking operation) might still be executed on a thread pool, but if any pre-processing before the network call is heavy, or if the network call itself is inadvertently synchronous, it can block the main thread.
*   **Impact:** Application unresponsiveness (DoS), poor user experience, potential ANR (Application Not Responding) dialogs.
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   **Developers:**  Always use `subscribeOn()` to specify the thread for long-running operations (e.g., `Schedulers.io()` for network and disk I/O). Use `observeOn(AndroidSchedulers.mainThread())` *only* for updating the UI on the main thread. Implement timeouts using RxJava's `timeout()` operator to prevent indefinite blocking. Use Android's StrictMode to detect accidental main thread operations during development.

## Attack Surface: [Swallowed Exceptions and Silent Failures](./attack_surfaces/swallowed_exceptions_and_silent_failures.md)

*   **Description:**  Errors within Rx streams are not handled properly (missing or inadequate `onError` handlers), leading to silent failures and potentially masking underlying issues, including security vulnerabilities.
*   **How RxAndroid Contributes:** RxJava's (and thus RxAndroid's) error handling model requires explicit `onError` handlers in `Observable` subscriptions.  If these are omitted or poorly implemented, errors are silently ignored, a *direct* consequence of the Rx paradigm.
*   **Example:** A network request within an RxAndroid stream fails due to a network error or a server-side issue.  If the `Observable` doesn't have a properly implemented `onError` handler, the error will be swallowed, and the application might continue as if the request succeeded, leading to incorrect behavior or data inconsistencies.
*   **Impact:**  Application instability, incorrect data processing, masking of security vulnerabilities, difficult debugging.
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   **Developers:**  Always implement robust `onError` handlers for *all* `Observable` subscriptions, including those created with RxAndroid. Log all errors with sufficient detail (including stack traces) for debugging and auditing. Use a global error handler (`RxJavaPlugins.setErrorHandler`) to catch any unhandled exceptions that might slip through.  Use `retry()` and `onErrorResumeNext()` carefully, ensuring they don't hide critical errors or security-related exceptions.

