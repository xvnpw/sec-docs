# Attack Surface Analysis for gabime/spdlog

## Attack Surface: [Format String Injection Vulnerability](./attack_surfaces/format_string_injection_vulnerability.md)

*   **Description:** Exploiting format string vulnerabilities by injecting malicious format specifiers into log messages when user-controlled input is directly used as a format string argument in `spdlog` logging functions. This is a direct consequence of how `spdlog` processes format strings.
*   **spdlog Contribution:** `spdlog`'s logging functions utilize format strings similar to `printf`.  Directly passing user-controlled input as the format string argument makes the application vulnerable to format string injection via `spdlog`.
*   **Example:**  Code: `spdlog::info(user_input);` where `user_input` is attacker-controlled and set to `%x%x%x%x%n`. This can lead to reading stack memory (`%x`) or writing to arbitrary memory locations (`%n`).
*   **Impact:** Information disclosure (reading stack memory, potentially other memory regions), potential arbitrary code execution (in certain scenarios, though less common with modern mitigations), denial of service (application crash).
*   **Risk Severity:** **Critical**
*   **Mitigation Strategies:**
    *   **Mandatory Parameterized Logging:**  **Always** use parameterized logging with `spdlog`. Pass user input as arguments, not as part of the format string.  Example: `spdlog::info("User input: {}", user_input);`
    *   **Completely Avoid User Input as Format Strings:**  Never directly use user-provided input as the format string argument in `spdlog` logging functions. There is almost no legitimate use case for this pattern in secure applications.

## Attack Surface: [Path Traversal via Configurable Log File Paths](./attack_surfaces/path_traversal_via_configurable_log_file_paths.md)

*   **Description:** Exploiting path traversal vulnerabilities by manipulating configurable log file paths used by `spdlog` file sinks to write logs to arbitrary locations on the file system. This vulnerability arises from the application's configuration of `spdlog` file sinks.
*   **spdlog Contribution:** `spdlog` allows applications to configure file sinks and specify the log file path. If the application allows external configuration of these paths without proper validation, it becomes vulnerable to path traversal attacks when using `spdlog`'s file logging capabilities.
*   **Example:** Application configuration allows setting `log_file_path`. If set to `../../../../etc/passwd` and used to initialize a `spdlog::basic_logger_mt` sink, the application might attempt to write logs to `/etc/passwd` (permissions permitting, or to other sensitive locations).
*   **Impact:** Overwriting critical system files (potential denial of service or system instability), information disclosure (writing logs to locations accessible to unauthorized users, potentially exposing internal application data if log content is sensitive).
*   **Risk Severity:** **High**
*   **Mitigation Strategies:**
    *   **Strict Path Validation and Sanitization:**  Thoroughly validate and sanitize any user-provided or externally configurable log file paths *before* passing them to `spdlog` file sink configuration.
    *   **Allowlisting of Directories:**  Use an allowlist to restrict log file paths to a predefined set of allowed directories.
    *   **Enforce Absolute Paths:**  Require and enforce the use of absolute paths for log files, rejecting any relative path components in configurations.
    *   **Principle of Least Privilege (File System Permissions):** Run the application with minimal file system write permissions to limit the potential damage from path traversal vulnerabilities, even if they exist.

