# Threat Model Analysis for react-hook-form/react-hook-form

## Threat: [Uncontrolled Component Bypass (Direct Manipulation)](./threats/uncontrolled_component_bypass__direct_manipulation_.md)

*   **Threat:** Bypass of `react-hook-form`'s validation and data handling through direct DOM manipulation.
*   **Description:** An attacker uses browser developer tools or a malicious browser extension to directly modify the value of an input field *after* `react-hook-form` has performed its validation or to circumvent the validation process entirely. Because `react-hook-form` relies on uncontrolled components, it doesn't continuously monitor the DOM for changes made outside of its control. This allows the attacker to submit data that `react-hook-form`'s client-side validation would normally reject.
*   **Impact:** Submission of invalid or malicious data to the server, potentially leading to data corruption, security breaches (if server-side validation is weak or absent), or unexpected application behavior. The server might receive data that violates expected constraints.
*   **Affected Component:** `register` function (and the overall uncontrolled component paradigm of `react-hook-form`). The core issue is that `react-hook-form` trusts the initial state of the registered input and doesn't actively prevent direct DOM manipulation.
*   **Risk Severity:** High (if server-side validation is insufficient or relies on client-side validation). The severity is high because it directly undermines the intended validation process.
*   **Mitigation Strategies:**
    *   **Robust Server-Side Validation (Essential):** This is the *primary* and most crucial defense.  Always validate *all* submitted data on the server, independently of any client-side checks. Assume the client-side validation has been bypassed.
    *   Avoid mixing controlled and uncontrolled components for the same field. Ensure consistency in using `react-hook-form`.
    *   Minimize any direct DOM manipulation of form fields outside of `react-hook-form`'s control.

