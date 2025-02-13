# Attack Surface Analysis for permissions-dispatcher/permissionsdispatcher

## Attack Surface: [Missing or Incorrect `@NeedsPermission` Annotations](./attack_surfaces/missing_or_incorrect__@needspermission__annotations.md)

*   **Description:** Sensitive functions are not protected by the required permission checks, or the wrong permission is checked.  This is a *direct* misuse of the core annotation that PermissionsDispatcher provides.
*   **PermissionsDispatcher Contribution:** The entire purpose of PermissionsDispatcher is to enforce permission checks via these annotations.  Missing or incorrect annotations are a fundamental failure to use the library correctly.
*   **Example:** A function that accesses the user's location is not annotated with `@NeedsPermission(Manifest.permission.ACCESS_FINE_LOCATION)`, or is incorrectly annotated with `@NeedsPermission(Manifest.permission.ACCESS_COARSE_LOCATION)` when fine-grained location is required.
*   **Impact:** Unauthorized access to sensitive data or functionality (e.g., contacts, camera, location, microphone).  This is a *direct* bypass of the intended security mechanism.
*   **Risk Severity:** Critical
*   **Mitigation Strategies:**
    *   **Developer:** Rigorous code reviews, mandatory static analysis to detect missing or incorrect annotations, comprehensive unit and integration testing to verify permission checks for *all* sensitive functions, strict adherence to the principle of least privilege.  Consider using a checklist or automated tool to ensure all sensitive functions are properly annotated.
    *   **User:** (Limited direct mitigation) Be extremely cautious about granting permissions to apps, especially if the requested permissions seem excessive or unnecessary for the app's stated functionality.

## Attack Surface: [Logic Errors in Permission Handling Callbacks (`onPermissionDenied`, `onNeverAskAgain`)](./attack_surfaces/logic_errors_in_permission_handling_callbacks___onpermissiondenied____onneveraskagain__.md)

*   **Description:** Flaws in the implementation of `onPermissionDenied` or `onNeverAskAgain` callbacks lead to incorrect behavior or bypasses of the permission system, *even if* the `@NeedsPermission` annotation is present and correct.
*   **PermissionsDispatcher Contribution:** PermissionsDispatcher provides these callbacks as part of its API.  The *correctness* and *security* of their implementation are entirely the developer's responsibility, and errors here directly impact the library's effectiveness.
*   **Example:** The `onPermissionDenied` handler for camera access has a bug that, due to a race condition or incorrect state management, allows the camera access to proceed *after* the user has denied the permission.  Or, the `onNeverAskAgain` handler fails to properly prevent subsequent attempts to access a permanently denied resource.
*   **Impact:** Bypassing of permission checks (even after denial); unexpected application behavior; potential data leaks or unauthorized actions.  The user's explicit denial of permission is ignored.
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   **Developer:** Thoroughly test *all* callback handlers, including edge cases, error conditions, and concurrent access scenarios.  Ensure that the application behaves correctly and securely when permissions are denied or permanently denied.  Use robust state management and synchronization mechanisms to prevent race conditions.  Consider using a finite state machine to model the permission request and handling flow.
    *   **User:** (Limited direct mitigation) Monitor app behavior closely; report any suspicious activity or unexpected permission requests, especially if the app seems to be ignoring your permission choices.

## Attack Surface: [`@OnNeverAskAgain` Misuse](./attack_surfaces/_@onneveraskagain__misuse.md)

*   **Description:** Incorrect handling of the `onNeverAskAgain` callback, leading to functionality bypasses or unexpected behavior. This is a specific, high-risk subset of the previous point.
*   **PermissionsDispatcher Contribution:** The `onNeverAskAgain` callback is a core part of the PermissionsDispatcher API, designed to handle the case where the user has permanently denied a permission. Misusing it directly undermines the user's control over their privacy.
*   **Example:** The app continues to attempt a microphone operation even after the user has selected "Never Ask Again" for microphone permission, potentially leading to a crash or, worse, a silent bypass of the user's choice.
*   **Impact:** Bypassing of the user's *permanent* denial of permission; application crashes or unexpected behavior; severe erosion of user trust.
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   **Developer:** Implement the `onNeverAskAgain` handler meticulously to *guarantee* that the permanently denied permission is *never* requested again, and that the associated functionality is *completely* disabled or handled gracefully through an alternative, permission-less flow. Provide clear and informative UI feedback to the user about the permanent denial.
    *   **User:** (Limited direct mitigation) Be aware of the "Never Ask Again" option and its implications. If an app seems to be ignoring this choice, report it and consider uninstalling the app.

