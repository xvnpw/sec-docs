# Attack Surface Analysis for immerjs/immer

## Attack Surface: [Draft Leakage](./attack_surfaces/draft_leakage.md)

*   **Description:** Exposing the Immer draft object outside the `produce` callback function, allowing unintended modifications.
    *   **Immer Contribution:** Immer *provides* the draft object as a mutable proxy. The vulnerability is the *misuse* of this core feature by exposing the draft.
    *   **Example:**
        ```javascript
        let leakedDraft;
        const newState = produce(oldState, (draft) => {
          leakedDraft = draft; // The leak!
          draft.x = 10;
        });
        leakedDraft.y = 20; // Modification outside produce - breaks immutability
        ```
    *   **Impact:** Breaks immutability, leading to unpredictable application state, potential race conditions, and data corruption. Could be leveraged to bypass security checks if state is used for authorization.
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   **Code Reviews:** Thoroughly review code to ensure drafts are never assigned to variables outside the `produce` callback.
        *   **Linters:** Use ESLint with rules like `no-restricted-syntax` to prevent assigning the draft to external variables. A custom ESLint rule could be created specifically for this.
        *   **Encapsulation:** Design state updates to be self-contained within the `produce` function.
        *   **Avoid Global/Shared Variables:** Do not store the draft in global or shared mutable variables.

## Attack Surface: [Disabling Auto-Freezing (`setAutoFreeze(false)`)](./attack_surfaces/disabling_auto-freezing___setautofreeze_false___.md)

*   **Description:** Turning off Immer's automatic freezing of the produced state, allowing for direct modification of the result.
    *   **Immer Contribution:** Immer *provides* the `setAutoFreeze` option. The vulnerability is disabling this safety feature without alternative safeguards.
    *   **Example:**
        ```javascript
        setAutoFreeze(false);
        const newState = produce(oldState, (draft) => {
          draft.x = 10;
        });
        newState.x = 20; // Direct modification - no error, but breaks immutability
        ```
    *   **Impact:** Loss of immutability guarantees, leading to unpredictable behavior, potential data corruption, and circumvention of intended state update logic.
    *   **Risk Severity:** High (if immutability is relied upon)
    *   **Mitigation Strategies:**
        *   **Avoid Disabling:** Strongly prefer *not* disabling `setAutoFreeze`.
        *   **Justification and Documentation:** If disabling is *absolutely* necessary, clearly document the reason and implications.
        *   **Manual Freezing/Cloning:** If disabled, implement *manual* deep freezing or cloning of the produced state *immediately* after the `produce` call. Use a robust deep-freezing library.
        *   **Alternative Immutability Libraries:** Consider a different immutability library if performance is critical and freezing is the bottleneck.

