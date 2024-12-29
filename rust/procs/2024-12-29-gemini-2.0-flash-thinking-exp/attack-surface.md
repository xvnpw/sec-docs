* **Exposure of Sensitive Process Information**
    * **Description:** The `procs` library allows access to various attributes of running processes, some of which can contain sensitive information.
    * **How `procs` Contributes to the Attack Surface:** `procs` provides the functionality to retrieve this process information, making it readily available to the application.
    * **Example:** An application uses `procs` to list all running processes and displays their command-line arguments in a debugging interface. An attacker could observe the command line of a process containing database credentials or API keys.
    * **Impact:** Leakage of sensitive data like credentials, API keys, internal paths, or configuration details. This can lead to unauthorized access, data breaches, or further attacks.
    * **Risk Severity:** High
    * **Mitigation Strategies:**
        * Carefully consider which process information is absolutely necessary for the application's functionality.
        * Avoid displaying or logging raw process information, especially command-line arguments and environment variables.
        * Sanitize and redact any sensitive information before displaying or logging.
        * Implement strict access controls to limit who can access process information within the application.

* **Exploitation of User-Controlled Filtering Parameters**
    * **Description:** If the application allows users to provide input that is directly used as filtering parameters for `procs` functions, it can be exploited.
    * **How `procs` Contributes to the Attack Surface:** `procs` offers filtering capabilities based on various process attributes. If these filters are driven by user input without proper validation, it creates a vulnerability.
    * **Example:** An application allows users to search for processes by name. An attacker could input a wildcard or a very broad pattern that forces `procs` to iterate through a large number of processes, leading to a denial-of-service.
    * **Impact:** Denial-of-service (DoS) due to excessive resource consumption. Potential for information gathering by crafting specific filters to identify processes of interest.
    * **Risk Severity:** High
    * **Mitigation Strategies:**
        * Sanitize and validate all user-provided input before using it as filtering criteria for `procs` functions.
        * Implement whitelisting of allowed characters or patterns for filtering.
        * Implement rate limiting or resource quotas on filtering operations.
        * Avoid directly exposing the full filtering capabilities of `procs` to untrusted users.