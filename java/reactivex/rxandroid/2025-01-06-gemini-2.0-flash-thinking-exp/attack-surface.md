# Attack Surface Analysis for reactivex/rxandroid

## Attack Surface: [UI Thread Blocking (Responsiveness Issues)](./attack_surfaces/ui_thread_blocking__responsiveness_issues_.md)

* **Description:** Operations intended for background threads are executed on the main UI thread, causing the application to freeze or become unresponsive.
* **How RxAndroid Contributes:** Incorrect use of `observeOn(AndroidSchedulers.mainThread())` for long-running or computationally intensive tasks forces these operations onto the UI thread.
* **Example:**
    ```java
    Observable.fromCallable(() -> performHeavyCalculation()) // Heavy operation
        .observeOn(AndroidSchedulers.mainThread())
        .subscribe(result -> updateUI(result)); // UI update
    ```
* **Impact:** Denial of Service (DoS) from a user experience perspective, leading to frustration and potential abandonment of the application. Can be exploited by triggering these heavy operations repeatedly.
* **Risk Severity:** High
* **Mitigation Strategies:**
    * Offload heavy tasks to background threads: Use `subscribeOn(Schedulers.io())` or `subscribeOn(Schedulers.computation())` for operations that should not block the UI.
    * Avoid long-running operations directly on the main thread:  Break down complex tasks into smaller, asynchronous units.
    * Use `observeOn(AndroidSchedulers.mainThread())` only for UI updates: Ensure that only the final step of updating the UI happens on the main thread.

