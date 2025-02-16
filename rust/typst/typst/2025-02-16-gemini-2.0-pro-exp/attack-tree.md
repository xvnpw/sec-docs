# Attack Tree Analysis for typst/typst

Objective: To achieve Remote Code Execution (RCE) on the server hosting the application that uses Typst, or to exfiltrate sensitive data processed by or exposed through Typst.

## Attack Tree Visualization

```
                                     +-------------------------------------------------+
                                     |  Achieve RCE or Data Exfiltration via Typst     |
                                     +-------------------------------------------------+
                                                       |
          +------------------------------------------------------------------------------------------------+
          |                                                |                                                |
+---------------------+                      +-------------------------+                      +-------------------------+
|  (Omitted)         |                      |  Exploit Typst          |                      |  Exploit Typst          |
|                      |                      |  Package Management     |                      |  Input Handling         |
+---------------------+                      +-------------------------+                      +-------------------------+
                                                       |                                                |
                                         +-----------------+-----------------+                 +---------+---------+
                                         |                 |                 |                 |                   |
                                         |  3. Malicious   |                 |                 |  5. Unsanitized  |  6. Path Traversal |
                                         |  Package       |                 |                 |  Input in        |  in File Access   |
                                         |  [CRITICAL]   |                 |                 |  Functions       |  (e.g., images)   |
                                         |                  |                 |                 |  [CRITICAL]   |  [HIGH-RISK]     |
                                         +-----------------+-----------------+                 +-----------------+-------------------+
                                                       |                                                |                   |
                                         +---------+-----+                                 +---------+-----+ +---------+-----+
                                         | [HIGH-RISK]    |                                 | [HIGH-RISK]    | [HIGH-RISK]    |
                                         | 3a.     | 3b. |                                 | 5a.     | 5b. | | 6a.     |     |
                                         | Typst   | Typst|                                 | Exploit | Exploit| | Read    |     |
                                         | Code    | Code |                                 | #read   | #image | | Arbitrary|     |
                                         | [CRITICAL]| Init |                                 | [CRITICAL]| [CRITICAL]| | Files   |     |
                                         |         | [CRITICAL]|                                 |         |         | | [CRITICAL]|     |
                                         +---------+-----+                                 +---------+-----+ +---------+-----+
```

## Attack Tree Path: [I. Exploit Typst Package Management](./attack_tree_paths/i__exploit_typst_package_management.md)

Overall Description: This attack vector focuses on leveraging vulnerabilities within Typst's package management system to introduce malicious code.

3. Malicious Package [CRITICAL]
Description: An attacker publishes a malicious package to the Typst package repository. This package contains code designed to compromise the system when the package is installed or used.
Likelihood: Medium
Impact: Very High (RCE)
Effort: Medium
Skill Level: Intermediate
Detection Difficulty: Medium/Hard
Sub-Vectors:
3a. Typst Code [CRITICAL]
Description: The malicious package contains harmful Typst code within its main files. This code is executed when the package's functions are called.
Likelihood: Medium
Impact: Very High (RCE)
Effort: Medium
Skill Level: Intermediate
Detection Difficulty: Medium
3b. Typst Code (Init) [CRITICAL]
Description: The malicious package contains harmful Typst code that is executed during the package's initialization phase (e.g., when it's first imported or installed). This can be more stealthy than code in the main files.
Likelihood: Medium
Impact: Very High (RCE)
Effort: Medium
Skill Level: Intermediate
Detection Difficulty: Hard

## Attack Tree Path: [II. Exploit Typst Input Handling](./attack_tree_paths/ii__exploit_typst_input_handling.md)

Overall Description: This attack vector targets vulnerabilities in how Typst processes user-supplied input, particularly through built-in functions.

5. Unsanitized Input in Functions [CRITICAL]
Description: Typst functions that take user input (e.g., file paths, URLs, or data to be embedded) may not properly sanitize this input. This can lead to code injection or other vulnerabilities.
Likelihood: Medium
Impact: Very High (RCE, Data Exfiltration)
Effort: Medium
Skill Level: Intermediate
Detection Difficulty: Medium
Sub-Vectors:
5a. Exploit #read [CRITICAL]
Description: The #read function, used to read the contents of files, is exploited by providing malicious input (e.g., a crafted path or file content) that is interpreted as Typst code or leads to unintended file access.
Likelihood: Medium
Impact: High (Code Injection, Arbitrary File Read)
Effort: Medium
Skill Level: Intermediate
Detection Difficulty: Medium
5b. Exploit #image [CRITICAL]
Description: The #image function, used to embed images, is exploited by providing a malicious image file or path. This could lead to code injection if the image metadata or content is interpreted as Typst code, or to arbitrary file access.
Likelihood: Medium
Impact: High (Code Injection, Arbitrary File Read/Write)
Effort: Medium
Skill Level: Intermediate
Detection Difficulty: Medium

6. Path Traversal in File Access [HIGH-RISK]
Description: Typst functions that access files (e.g., #read, #image) are vulnerable to path traversal attacks if they don't properly sanitize file paths. An attacker can use ../ or similar sequences to access files outside the intended directory.
Likelihood: Medium
Impact: High (Data Exfiltration, Potentially RCE)
Effort: Low/Medium
Skill Level: Intermediate
Detection Difficulty: Easy/Medium
Sub-Vectors:
6a. Read Arbitrary Files [CRITICAL]
Description: An attacker uses path traversal techniques to read files outside the intended directory, potentially accessing sensitive data or configuration files.
Likelihood: Medium
Impact: High (Information Disclosure, Potential for further compromise)
Effort: Low
Skill Level: Intermediate
Detection Difficulty: Easy

