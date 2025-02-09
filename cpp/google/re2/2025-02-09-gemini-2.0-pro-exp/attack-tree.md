# Attack Tree Analysis for google/re2

Objective: To cause a Denial of Service (DoS) by exploiting vulnerabilities or weaknesses in the application's use of the re2 library.

## Attack Tree Visualization

```
Compromise Application via re2
├── 1. Denial of Service (DoS) (High Probability) [HIGH RISK]
│   ├── 1.1  Resource Exhaustion (CPU) [HIGH RISK]
│   │   ├── 1.1.1  Crafted Regular Expression (Catastrophic Backtracking) [CRITICAL]
│   │   │   ├── 1.1.1.1  Nested Quantifiers (e.g., (a+)+) [HIGH RISK]
│   │   │   ├── 1.1.1.2  Overlapping Alternations with Quantifiers (e.g., (a|a)+) [HIGH RISK]
│   │   │   └── 1.1.1.3  Repetitions of Complex Groups (e.g., (complex_group){1000}) [HIGH RISK]
│   └── 1.2  Application-Level Amplification [HIGH RISK]
│       ├── 1.2.1  Repeated Regex Matching on User Input [CRITICAL] [HIGH RISK]
│       │   ├── 1.2.1.1  Looping over Input and Applying Regex [HIGH RISK]
│       └── 1.2.2  Regex Matching in Critical Code Paths [CRITICAL] [HIGH RISK]
│           └── 1.2.2.1  Regex in Authentication/Authorization Logic [HIGH RISK]
```

## Attack Tree Path: [1. Denial of Service (DoS) [HIGH RISK]](./attack_tree_paths/1__denial_of_service__dos___high_risk_.md)

*   **Description:** The attacker aims to make the application unavailable to legitimate users by overwhelming it with requests or causing it to consume excessive resources.
*   **Overall Likelihood:** High
*   **Overall Impact:** High (application unavailability)

## Attack Tree Path: [1.1 Resource Exhaustion (CPU) [HIGH RISK]](./attack_tree_paths/1_1_resource_exhaustion__cpu___high_risk_.md)

*   **Description:** The attacker crafts input that causes the re2 library to consume a large amount of CPU time, slowing down or crashing the application.
*   **Overall Likelihood:** Medium
*   **Overall Impact:** High

## Attack Tree Path: [1.1.1 Crafted Regular Expression (Catastrophic Backtracking) [CRITICAL]](./attack_tree_paths/1_1_1_crafted_regular_expression__catastrophic_backtracking___critical_.md)

*   **Description:**  The attacker provides a regular expression that, while not triggering traditional exponential backtracking (which re2 avoids), still results in high CPU usage due to polynomial complexity or other re2-specific performance characteristics.
*   **Likelihood:** Medium
*   **Impact:** High
*   **Effort:** Medium
*   **Skill Level:** Intermediate
*   **Detection Difficulty:** Medium

## Attack Tree Path: [1.1.1.1 Nested Quantifiers (e.g., `(a+)+`) [HIGH RISK]](./attack_tree_paths/1_1_1_1_nested_quantifiers__e_g_____a+_+____high_risk_.md)

*   **Description:**  A regular expression with nested quantifiers (e.g., `+` inside another `+`) can, in some cases, lead to increased processing time, even with re2. The specific impact depends on the input string.
*   **Example:** `(a+)+$` against input "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaab"

## Attack Tree Path: [1.1.1.2 Overlapping Alternations with Quantifiers (e.g., `(a|a)+`) [HIGH RISK]](./attack_tree_paths/1_1_1_2_overlapping_alternations_with_quantifiers__e_g_____aa_+____high_risk_.md)

*   **Description:**  Alternations (using `|`) where the alternatives overlap, combined with quantifiers, can also lead to performance issues.
*   **Example:** `(a|aa|aaa)+$`

## Attack Tree Path: [1.1.1.3 Repetitions of Complex Groups (e.g., `(complex_group){1000}`) [HIGH RISK]](./attack_tree_paths/1_1_1_3_repetitions_of_complex_groups__e_g_____complex_group_{1000}____high_risk_.md)

*   **Description:**  Repeating a complex group many times can increase processing time, especially if the "complex_group" itself contains patterns that are not highly optimized.
*   **Example:** `(\w+:\d+;){1000}`

## Attack Tree Path: [1.2 Application-Level Amplification [HIGH RISK]](./attack_tree_paths/1_2_application-level_amplification__high_risk_.md)

*   **Description:** The application's design exacerbates the impact of a slow regex. Even a moderately slow regex can become a DoS vulnerability if the application handles it poorly.
*   **Overall Likelihood:** Medium
*   **Overall Impact:** High

## Attack Tree Path: [1.2.1 Repeated Regex Matching on User Input [CRITICAL] [HIGH RISK]](./attack_tree_paths/1_2_1_repeated_regex_matching_on_user_input__critical___high_risk_.md)

*   **Description:** The application applies the same (potentially slow) regex multiple times to the same or similar user-provided input.
*   **Likelihood:** Medium
*   **Impact:** High
*   **Effort:** Low
*   **Skill Level:** Intermediate
*   **Detection Difficulty:** Easy

## Attack Tree Path: [1.2.1.1 Looping over Input and Applying Regex [HIGH RISK]](./attack_tree_paths/1_2_1_1_looping_over_input_and_applying_regex__high_risk_.md)

*   **Description:**  The application iterates through user input (e.g., a list of strings) and applies the regex to each element.  A single malicious input can trigger multiple slow matches.
*   **Example:**
    ```python
    for item in user_provided_list:
        if re2.match(user_provided_regex, item):
            # ... process the match ...
    ```

## Attack Tree Path: [1.2.2 Regex Matching in Critical Code Paths [CRITICAL] [HIGH RISK]](./attack_tree_paths/1_2_2_regex_matching_in_critical_code_paths__critical___high_risk_.md)

*   **Description:** The regex is used in a performance-sensitive part of the application, such as authentication or authorization. Even a small delay can have a significant impact.
*   **Likelihood:** Low
*   **Impact:** Very High
*   **Effort:** Low
*   **Skill Level:** Novice
*   **Detection Difficulty:** Easy

## Attack Tree Path: [1.2.2.1 Regex in Authentication/Authorization Logic [HIGH RISK]](./attack_tree_paths/1_2_2_1_regex_in_authenticationauthorization_logic__high_risk_.md)

*   **Description:**  The regex is used to validate user credentials or permissions. A slow regex here can block legitimate users from accessing the application.
*   **Example:** Using a regex to validate a complex password format *during every login attempt*.

