# Attack Tree Analysis for krzysztofzablocki/sourcery

Objective: Achieve RCE or Information Disclosure via Sourcery

## Attack Tree Visualization

Goal: Achieve RCE or Information Disclosure via Sourcery
├── 1.  RCE via Template Injection
│   ├── 1.1  Exploit Unsanitized Input in Template Variables [CRITICAL]
│   │   ├── 1.1.1  Identify Template Variables
│   │   ├── 1.1.2  Craft Malicious Input
│   │   ├── 1.1.3  Deliver Malicious Input [CRITICAL]
│   │   ├── 1.1.4  Trigger Template Rendering
│   │   ---> High-Risk Path: 1.1.1 -> 1.1.2 -> 1.1.3 -> 1.1.4
│   ├── 1.3  Exploit Misconfigured Template Permissions [CRITICAL]
│   │   ├── 1.3.1  Identify Writable Template Directories
│   │   ├── 1.3.2  Overwrite Existing Template
│   │   ├── 1.3.3  Trigger Template Rendering
│   │   ---> High-Risk Path: 1.3.1 -> 1.3.2 -> 1.3.3
│   ├── 1.4 Exploit Sourcery's Inline Swift Code Execution [CRITICAL]
│   │   ├── 1.4.1 Identify Inline Swift Code Blocks
│   │   ├── 1.4.2 Inject Malicious Code [CRITICAL]
│   │   ├── 1.4.3 Deliver and Trigger
│   │   ---> High-Risk Path: 1.4.1 -> 1.4.2 -> 1.4.3
├── 2.  Information Disclosure via Template Manipulation
│   ├── 2.2  Access Unauthorized Templates
│   │   ├── 2.2.2  Attempt Path Traversal [CRITICAL]

## Attack Tree Path: [1. RCE via Template Injection](./attack_tree_paths/1__rce_via_template_injection.md)

*   **1.1 Exploit Unsanitized Input in Template Variables [CRITICAL]**

    *   **Description:** This is the most common and direct path to RCE.  It relies on the application failing to properly sanitize or validate user-supplied input that is then used within Sourcery templates.  If an attacker can inject arbitrary code into a template variable, they can achieve code execution when the template is rendered.
    *   **High-Risk Path (1.1.1 -> 1.1.2 -> 1.1.3 -> 1.1.4):**
        *   **1.1.1 Identify Template Variables:**
            *   *Action:* The attacker analyzes the application's source code and any available Sourcery templates to identify variables that are used within the templates.  This is a reconnaissance step.
            *   *Example:*  Finding a template that uses `{{ user.name }}` where `user.name` is taken from user input.
        *   **1.1.2 Craft Malicious Input:**
            *   *Action:* The attacker constructs a malicious input string that, when substituted into the template variable, will execute arbitrary code.  The specific payload depends on the templating engine (e.g., Stencil) and its syntax.
            *   *Example (Stencil):*  `{{ system("id") }}` (if `system` is exposed) or more complex Swift code to achieve the desired outcome.
        *   **1.1.3 Deliver Malicious Input [CRITICAL]:**
            *   *Action:* The attacker finds a way to inject their crafted input into the application's data flow so that it reaches the identified template variable. This is highly application-specific and might involve exploiting a web form, API endpoint, or other input vector.
            *   *Example:*  Submitting a form where the "username" field is vulnerable and feeds directly into the `user.name` template variable.
        *   **1.1.4 Trigger Template Rendering:**
            *   *Action:* The attacker triggers the application to render the template containing the malicious input. This often happens automatically as part of the application's normal workflow.
            *   *Example:*  Simply viewing a profile page that renders the `user.name` variable.

*   **1.3 Exploit Misconfigured Template Permissions [CRITICAL]**

    *   **Description:** This attack vector relies on the Sourcery templates being stored in a location that is writable by the application's runtime user.  If an attacker can modify a template, they can inject malicious code.
    *   **High-Risk Path (1.3.1 -> 1.3.2 -> 1.3.3):**
        *   **1.3.1 Identify Writable Template Directories:**
            *   *Action:* The attacker attempts to determine if the directory where Sourcery templates are stored is writable by the user under which the application is running. This might involve probing the file system or exploiting other vulnerabilities to gain access.
            *   *Example:*  Finding that the `/var/www/app/templates` directory is writable by the `www-data` user.
        *   **1.3.2 Overwrite Existing Template:**
            *   *Action:* The attacker overwrites a legitimate Sourcery template with a malicious one containing their code injection payload.
            *   *Example:*  Replacing `profile.stencil` with a version that includes `{{ system("rm -rf /") }}` (a destructive example).
        *   **1.3.3 Trigger Template Rendering:**
            *   *Action:* The attacker waits for or triggers the application to use the modified template.  This could happen automatically or require some action by the attacker.
            *   *Example:*  Visiting a page that uses the modified `profile.stencil` template.

*   **1.4 Exploit Sourcery's Inline Swift Code Execution [CRITICAL]**

    *   **Description:**  This attack vector targets inline Swift code blocks within Sourcery templates. If input to these code blocks is not properly sanitized, an attacker can inject malicious Swift code.
    *   **High-Risk Path (1.4.1 -> 1.4.2 -> 1.4.3):**
        *   **1.4.1 Identify Inline Swift Code Blocks:**
            *   *Action:* The attacker examines the Sourcery templates to find instances where inline Swift code is used (e.g., for complex logic or calculations).
            *   *Example:* Finding a template with a block like `{% for item in items %}{% if item.name == userInput %}...{% endif %}{% endfor %}` where `userInput` is not sanitized.
        *   **1.4.2 Inject Malicious Code [CRITICAL]:**
            *   *Action:* The attacker crafts input that, when used within the inline Swift code, will execute arbitrary code. This requires understanding Swift syntax and how the input is used within the code block.
            *   *Example:*  Providing input like `"test\" == \"test\" { print(\"Hello from injected code!\"); exit(1); } //"` to the `userInput` variable in the previous example.
        *   **1.4.3 Deliver and Trigger:**
            *   *Action:*  The attacker delivers the malicious input to the application and triggers the template rendering, causing the injected Swift code to execute. This is similar to steps 1.1.3 and 1.1.4.
            *   *Example:* Submitting a form that provides the malicious input to a field that is used within the inline Swift code block.

## Attack Tree Path: [2. Information Disclosure via Template Manipulation](./attack_tree_paths/2__information_disclosure_via_template_manipulation.md)

*  **2.2 Access Unauthorized Templates**
    * **2.2.2 Attempt Path Traversal [CRITICAL]:**
        *   **Description:** This is a critical step in attempting to access templates outside of the intended directory. It relies on vulnerabilities in how the application handles template paths.
        *   *Action:* The attacker tries to use path traversal techniques (e.g., `../`) in the template path to access files outside the designated template directory.
        *   *Example:* If the application loads templates based on user input like `/templates/<user_input>`, the attacker might try `/templates/../../etc/passwd` to read the system's password file.

