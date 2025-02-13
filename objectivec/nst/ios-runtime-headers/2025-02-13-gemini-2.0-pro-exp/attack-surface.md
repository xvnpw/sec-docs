# Attack Surface Analysis for nst/ios-runtime-headers

## Attack Surface: [1. Undocumented API Exploitation](./attack_surfaces/1__undocumented_api_exploitation.md)

*   *Description:* Attackers leverage knowledge of private APIs to exploit vulnerabilities within those undocumented functions.
    *   *How `ios-runtime-headers` Contributes:* Provides the header files, revealing function signatures, class structures, and method names, making reverse engineering and vulnerability discovery significantly easier.  This is the *direct* contribution.
    *   *Example:* A private API in `CoreTelephony` (revealed by the headers) might have an unchecked buffer when processing a specific type of SMS message. An attacker could craft a malicious SMS to trigger a buffer overflow, potentially gaining code execution.
    *   *Impact:* Code execution, privilege escalation, data exfiltration, denial of service.
    *   *Risk Severity:* Critical
    *   *Mitigation Strategies:*
        *   **Developer:** Avoid using private APIs. If unavoidable, perform extensive fuzzing and security testing of the specific API calls. Implement robust input validation and error handling.  Dynamic analysis is crucial.
        *   **User:** No direct mitigation; relies on developer actions.

## Attack Surface: [2. API Instability and Breakage](./attack_surfaces/2__api_instability_and_breakage.md)

*   *Description:* Private APIs can change or be removed without notice in iOS updates, leading to application crashes, unexpected behavior, or *security vulnerabilities*.
    *   *How `ios-runtime-headers` Contributes:* Encourages the use of APIs that are not guaranteed to be stable across iOS versions, making the application reliant on undocumented behavior.
    *   *Example:* An app uses a private API to access a specific system setting. An iOS update changes the format of that setting or removes the API entirely.  If error handling is poor, this could lead to a denial-of-service or, if the setting controlled a security feature, a vulnerability.
    *   *Impact:* Application instability, data corruption, denial of service, *potential security vulnerabilities due to unexpected behavior or failed security checks*.
    *   *Risk Severity:* High
    *   *Mitigation Strategies:*
        *   **Developer:** Avoid private APIs. If unavoidable, use runtime checks (`respondsToSelector:`, `instancesRespondToSelector:`, `class_respondsToSelector:`) to verify API availability *before* calling it. Implement fallback mechanisms to use alternative (public) APIs or gracefully degrade functionality. Thoroughly test on all supported iOS versions and *immediately* after each iOS update.  Consider how changes to the API could impact security.
        *   **User:** No direct mitigation; relies on developer actions.

## Attack Surface: [3. Security Mechanism Bypass](./attack_surfaces/3__security_mechanism_bypass.md)

*   *Description:* Private APIs might offer ways to circumvent security restrictions imposed by the public SDK (e.g., sandbox restrictions, permission checks).
    *   *How `ios-runtime-headers` Contributes:* Exposes APIs that might not be subject to the same security scrutiny as public APIs, potentially providing unintended access to resources or capabilities. The headers are the *direct* enabler.
    *   *Example:* A private API in a framework related to file system access might allow writing to a directory outside the application's sandbox, bypassing standard iOS security controls.
    *   *Impact:* Data exfiltration, unauthorized access to system resources, privilege escalation.
    *   *Risk Severity:* High
    *   *Mitigation Strategies:*
        *   **Developer:** Avoid private APIs. If unavoidable, carefully analyze the security implications of each API call. Implement additional security checks (e.g., validating file paths, checking permissions) even if the private API *appears* to grant access.  Assume the private API *does not* perform the same security checks as a public API.
        *   **User:** No direct mitigation; relies on developer actions.

