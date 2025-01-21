# Attack Surface Analysis for bettererrors/better_errors

## Attack Surface: [Source Code Exposure](./attack_surfaces/source_code_exposure.md)

**Description:**  The application's source code is revealed to users when an error occurs.

**How `better_errors` contributes to the attack surface:** `better_errors` displays snippets of the source code surrounding the line where the error occurred, making it easily accessible within the error page.

**Example:** An error occurs in a controller action that handles user authentication. `better_errors` displays the code where database credentials or secret keys are used.

**Impact:**  Exposure of sensitive information like API keys, database credentials, internal logic, and algorithms. This can lead to unauthorized access, data breaches, and a deeper understanding of application vulnerabilities for attackers.

**Risk Severity:** High

**Mitigation Strategies:**
* **Ensure `better_errors` is strictly limited to development and test environments.**
* **Avoid hardcoding sensitive information directly in the code.** Utilize environment variables or secure configuration management.
* **Review code regularly for accidental inclusion of sensitive data.**

## Attack Surface: [Variable Inspection](./attack_surfaces/variable_inspection.md)

**Description:** The values of local and instance variables at the point of the error are exposed.

**How `better_errors` contributes to the attack surface:** `better_errors` provides an interface to inspect the values of variables within the call stack at the time of the error.

**Example:** An error occurs while processing user data. `better_errors` reveals the value of a variable containing a user's password or social security number.

**Impact:** Exposure of sensitive user data, session tokens, or internal application state. This can lead to identity theft, session hijacking, and further exploitation of the application.

**Risk Severity:** High

**Mitigation Strategies:**
* **Ensure `better_errors` is strictly limited to development and test environments.**
* **Be mindful of the data stored in variables, especially when handling sensitive information.**
* **Implement proper data sanitization and validation to prevent sensitive data from being present in unexpected contexts.**

## Attack Surface: [Interactive Console (Pry/IRB)](./attack_surfaces/interactive_console__pryirb_.md)

**Description:**  An interactive Ruby console (Pry or IRB) is available within the error page.

**How `better_errors` contributes to the attack surface:** `better_errors` provides this interactive console in development environments, allowing users to execute arbitrary Ruby code within the application's context.

**Example:** An attacker gains access to a production environment where `better_errors` is mistakenly enabled. They can use the interactive console to read files, access the database, or execute system commands, effectively taking control of the server.

**Impact:**  Complete server compromise, including the ability to read, modify, or delete data, execute arbitrary code, and potentially pivot to other systems. This is the most critical vulnerability.

**Risk Severity:** Critical

**Mitigation Strategies:**
* **ABSOLUTELY ENSURE `better_errors` IS DISABLED IN PRODUCTION AND ANY NON-DEVELOPMENT ENVIRONMENT.** This is non-negotiable.
* **Restrict access to development and test environments to authorized personnel only.**

