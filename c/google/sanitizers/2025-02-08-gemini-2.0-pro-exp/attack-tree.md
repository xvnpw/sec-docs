# Attack Tree Analysis for google/sanitizers

Objective: To cause a denial-of-service (DoS) or achieve arbitrary code execution (ACE) in an application leveraging the Google Sanitizers, by exploiting the sanitizers themselves or their interaction with the application.

## Attack Tree Visualization

+-------------------------------------------------+
|  Attacker Goal: DoS or ACE via Sanitizer Exploit |
+-------------------------------------------------+
                 |
+-------------------------------------------------+
| 2. Exploit Application's  [HR] [CN]             |
|    Sanitizer Integration                       |
+-------------------------------------------------+
                 |
+-----------------+-----------------+
| 2.1     | 2.3     |
|  False  |  Improper|
|Positives| Error   |
|  [HR]   | Handling| [HR]
+-----------------+-----------------+
         |                 |
+---------+   +---------+---------+
|2.1.1    |   |2.3.1    |2.3.2    |
|Ignore   |   |Crash on |Disable  | [CN]
|Legit   |   |Sanitizer|Sanitizer|
|Input    |   |Report   |         |
|  [CN]   |   |  [HR]   |         |
+---------+   +---------+---------+

## Attack Tree Path: [2. Exploit Application's Sanitizer Integration [HR] [CN]](./attack_tree_paths/2__exploit_application's_sanitizer_integration__hr___cn_.md)

*   **Description:** This is the primary attack vector, focusing on how the application interacts with the sanitizers. Flaws in this integration are the most likely source of vulnerabilities.
*   **Why High-Risk:** More common due to developer errors, easier to exploit than finding bugs in the sanitizers themselves.
*   **Why Critical Node:** This is the main entry point; a successful attack here opens up multiple further attack paths.
*   **Sub-Vectors:**
    *   2.1 False Positives [HR]
    *   2.3 Improper Error Handling [HR]

## Attack Tree Path: [2.1 False Positives [HR]](./attack_tree_paths/2_1_false_positives__hr_.md)

*   **Description:** The application misinterprets or mishandles reports from the sanitizers, treating true positives as false positives.
*   **Why High-Risk:** Relatively common due to developer error or a misunderstanding of sanitizer reports. Can lead to significant vulnerabilities if legitimate reports are ignored.
*   **Sub-Vectors:**
    *   2.1.1 Ignore Legitimate Input [CN]

## Attack Tree Path: [2.1.1 Ignore Legitimate Input [CN]](./attack_tree_paths/2_1_1_ignore_legitimate_input__cn_.md)

*   **Description:** The application receives a sanitizer report indicating a security issue (e.g., buffer overflow, use-after-free), but incorrectly assumes it's a false positive and allows the malicious input to proceed.
*   **Why Critical Node:** This is a direct bypass of a security check. It allows an attacker to circumvent the protection offered by the sanitizer, potentially leading to arbitrary code execution or other severe consequences.
*   **Example:** An attacker crafts input that triggers a heap overflow. ASan detects this and generates a report. The application, however, has been configured (incorrectly) to ignore certain ASan reports, believing them to be false positives. The malicious input is processed, leading to memory corruption and potentially allowing the attacker to gain control.
*   **Mitigation:**
    *   *Never* ignore sanitizer reports without thorough investigation and verification.
    *   Establish a strict policy and procedure for handling sanitizer reports.
    *   Implement robust logging and alerting for all sanitizer reports.
    *   Use automated testing to verify that the application correctly handles various sanitizer reports.
    *   Provide developers with training on understanding and responding to sanitizer reports.

## Attack Tree Path: [2.3 Improper Error Handling [HR]](./attack_tree_paths/2_3_improper_error_handling__hr_.md)

*   **Description:** The application doesn't handle sanitizer reports correctly, leading to crashes, instability, or other undesirable behavior.
*   **Why High-Risk:** Can lead to Denial-of-Service (DoS) vulnerabilities and can expose the application to further attacks if error handling is poorly implemented.
*   **Sub-Vectors:**
    *   2.3.1 Crash on Sanitizer Report [HR]
    *   2.3.2 Disable Sanitizer [CN]

## Attack Tree Path: [2.3.1 Crash on Sanitizer Report [HR]](./attack_tree_paths/2_3_1_crash_on_sanitizer_report__hr_.md)

*   **Description:** The application is configured to terminate immediately upon receiving a sanitizer report.
*   **Why High-Risk:** Creates an easy-to-exploit Denial-of-Service (DoS) vulnerability. An attacker can craft input that triggers a sanitizer report (even a relatively benign one) and cause the application to crash.
*   **Example:** An attacker sends a specially crafted request that triggers a minor, non-exploitable integer overflow. UBSan detects this and generates a report. The application, due to improper error handling, immediately crashes upon receiving the report, making the service unavailable.
*   **Mitigation:**
    *   Implement graceful error handling for sanitizer reports. The application should *never* crash in a production environment due to a sanitizer report.
    *   Log the sanitizer report details for later analysis.
    *   If possible, attempt to recover from the error (e.g., by rejecting the specific request) without crashing the entire application.
    *   Provide informative error messages to the user (without revealing sensitive information).

## Attack Tree Path: [2.3.2 Disable Sanitizer [CN]](./attack_tree_paths/2_3_2_disable_sanitizer__cn_.md)

*   **Description:** In response to a sanitizer report (often a perceived false positive), the application or an administrator disables the sanitizer entirely.
*   **Why Critical Node:** This removes a crucial layer of defense, making the application significantly more vulnerable to a wide range of attacks. It's a catastrophic error in terms of security.
*   **Example:**  An application repeatedly triggers a false positive from TSan.  Instead of investigating the root cause, an administrator disables TSan to "fix" the issue. This leaves the application vulnerable to actual data races that TSan would have detected.
*   **Mitigation:**
    *   *Never* disable sanitizers in a production environment as a response to a report.
    *   Implement strict access controls and monitoring to prevent unauthorized disabling of sanitizers.
    *   If a false positive is suspected, investigate thoroughly. If it's confirmed, use targeted suppressions (if available and absolutely necessary) *instead* of disabling the entire sanitizer.
    *   Educate developers and administrators about the dangers of disabling sanitizers.

