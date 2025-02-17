# Mitigation Strategies Analysis for herotransitions/hero

## Mitigation Strategy: [Explicitly Hide/Clear Sensitive Views (Hero-Related Aspect)](./mitigation_strategies/explicitly_hideclear_sensitive_views__hero-related_aspect_.md)

**Description:**
1.  **Identify Sensitive Views:** As before, identify all UI elements with sensitive data.
2.  **Hide/Clear *Before* Hero Interaction:**  Crucially, ensure the hiding/clearing of sensitive content happens *before* you set any `Hero` properties (like `heroID` or `heroModifiers`) on *any* views involved in the transition, and *before* you initiate the transition using `hero.modalAnimationType`, `hero.navigationAnimationType`, or similar methods.  The order of operations is critical.  `Hero` takes a snapshot of the view hierarchy *when these properties are set*, so the sensitive data must be gone *before* that snapshot.
3.  **Restore *After* Transition Completion:** In the destination view controller's `viewDidAppear(_ animated: Bool)`, after the `Hero` transition has fully completed, unhide the view or repopulate the data.  This ensures the data is only visible after `Hero` is finished.

**Threats Mitigated:**
*   **Unintended Data Exposure During Transitions (Severity: High):** Prevents `Hero` from capturing sensitive data in its animation snapshots.

**Impact:**
*   **Unintended Data Exposure:** Significantly reduces the risk (close to elimination if implemented correctly).

**Currently Implemented:** (Example - Replace with your project's specifics)
*   Partially implemented in `LoginViewController.swift` (hiding password field).
*   Implemented in `ProfileViewController.swift` (clearing personal details).

**Missing Implementation:** (Example - Replace with your project's specifics)
*   Missing in `PaymentViewController.swift` (credit card details are not cleared/hidden during transition).
*   Missing in `SettingsViewController.swift` (API key field is not handled).

## Mitigation Strategy: [Use Placeholder Views (Directly with Hero)](./mitigation_strategies/use_placeholder_views__directly_with_hero_.md)

**Description:**
1.  **Identify Target Views:** Determine which sensitive views you want to animate.
2.  **Create Placeholder:** Create a non-sensitive placeholder view with the same frame as the sensitive view.
3.  **Hero Configuration on Placeholder *Only*:**  Apply all `Hero` modifiers (e.g., `heroID`, `heroModifiers`, `hero.modalAnimationType`) *exclusively* to the *placeholder* view.  Do *not* set any `Hero` properties on the sensitive view itself. This is the core of this mitigation.
4.  **Hide Sensitive View:** Hide the original sensitive view (`sensitiveView.isHidden = true`).
5.  **Initiate Transition:** Start the `Hero` transition. `Hero` will only see and animate the placeholder.
6.  **Swap Views in Destination:** In the destination view controller's `viewDidAppear`, after the transition completes:
    *   Remove the placeholder view.
    *   Unhide the *real* sensitive view (and populate it).

**Threats Mitigated:**
*   **Unintended Data Exposure During Transitions (Severity: High):** `Hero` never interacts directly with the sensitive view.

**Impact:**
*   **Unintended Data Exposure:** Eliminates the risk.

**Currently Implemented:** (Example)
*   Not currently implemented.

**Missing Implementation:** (Example)
*   Could be implemented for all transitions involving sensitive data.

## Mitigation Strategy: [Implement `HeroProgressUpdateObserver`](./mitigation_strategies/implement__heroprogressupdateobserver_.md)

**Description:** This strategy *directly* uses `Hero`'s API to handle interruptions.
1.  **Conform to Protocol:** Make your view controller conform to `HeroProgressUpdateObserver`.
2.  **Implement `heroDidUpdateProgress`:**
    ```swift
    func heroDidUpdateProgress(progress: Double) {
        if progress < 1.0 {
            // Transition interrupted.  Use Hero's state to help reset.
            hero.cancel() // Attempt to cancel the Hero transition.
            // Reset views to a safe state (consider using hero.modifiers for initial state).
        } else {
            // Transition completed.
            hero.finish() // Ensure Hero cleans up.
        }
    }
    ```
3.  **Register as Observer:**
    ```swift
    hero.progressUpdateObserver = self
    ```
4.  **Use `hero.cancel()` and `hero.finish()`:** The key here is to use `Hero`'s own methods (`cancel()` and `finish()`) to manage its internal state when interruptions occur. This is a direct interaction with the `Hero` API.
5. **Deregister observer:** Deregister the observer in `deinit` method of your view controller.

**Threats Mitigated:**
*   **State Corruption During Interrupted Transitions (Severity: High):** Leverages `Hero`'s internal mechanisms to handle interruptions gracefully.

**Impact:**
*   **State Corruption:** Significantly reduces the risk.

**Currently Implemented:** (Example)
*   Not currently implemented.

**Missing Implementation:** (Example)
*   Should be implemented in all view controllers using `Hero`.

## Mitigation Strategy: [Careful Use of `heroModifiers`](./mitigation_strategies/careful_use_of__heromodifiers_.md)

**Description:**
1.  **Understand Modifiers:** Thoroughly read the `Hero` documentation for each modifier (e.g., `.fade`, `.translate`, `.scale`, `.rotate`, etc.). Understand their parameters and interactions.
2.  **Minimal Modifiers:** Start with the *minimum* set of `heroModifiers` needed to achieve the desired effect. Avoid unnecessary complexity.
3.  **Test Combinations:** If using multiple modifiers, test them in various combinations to ensure they don't conflict or produce unexpected results.  `Hero`'s behavior can be complex when combining modifiers.
4.  **Avoid Overriding Defaults Unnecessarily:** Only override `Hero`'s default animation parameters if you have a specific reason to do so. The defaults are generally well-chosen.
5. **Use debug options:** Use `hero.debug()` to enable debug mode and get more information about the transition process.

**Threats Mitigated:**
*   **Improper Use of `heroModifiers` Leading to UI Bugs (Severity: Medium):** Reduces the likelihood of introducing visual glitches or animation errors due to incorrect modifier configurations.

**Impact:**
*   **UI Bugs:** Significantly reduces the risk.

**Currently Implemented:** (Example)
*   Basic modifiers are used, but not extensively tested in combination.

**Missing Implementation:** (Example)
*   More rigorous testing of modifier combinations is needed.
*   Documentation of which modifiers are used and why could be improved.

## Mitigation Strategy: [Leverage `hero.replace(with:)` Correctly (If Used)](./mitigation_strategies/leverage__hero_replace_with___correctly__if_used_.md)

**Description:**
1. **Understand `hero.replace(with:)`:** This method replaces the *entire* source view controller with the destination view controller *during* the transition. It's different from a standard push or modal presentation.
2. **Immediate Obscuring:** If the source view controller contains sensitive information, ensure the destination view controller, *immediately* upon being created and added to the view hierarchy by `hero.replace(with:)`, completely obscures any potentially sensitive areas. This might involve:
    *   Setting a solid background color.
    *   Placing an opaque view over the sensitive region.
    *   Ensuring that any data loading or view setup happens *synchronously* before the transition starts, so the destination view is fully ready.
3. **Avoid Asynchronous Loading:** Be extremely cautious about asynchronous data loading in the destination view controller when using `hero.replace(with:)`. If the data isn't ready *immediately*, there could be a brief flash of the underlying (potentially sensitive) content from the source view controller.

**Threats Mitigated:**
*   **Unintended Data Exposure During Transitions (Severity: High):** Specifically addresses the risk of exposure when using `hero.replace(with:)`.

**Impact:**
*   **Unintended Data Exposure:** Significantly reduces the risk if used correctly; increases the risk if used incorrectly.

**Currently Implemented:** (Example)
* Not currently used in the project.

**Missing Implementation:** (Example)
* If `hero.replace(with:)` is introduced in the future, these precautions must be taken.

