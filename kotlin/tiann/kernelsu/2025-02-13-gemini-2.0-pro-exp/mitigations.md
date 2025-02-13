# Mitigation Strategies Analysis for tiann/kernelsu

## Mitigation Strategy: [Filesystem-Based Detection](./mitigation_strategies/filesystem-based_detection.md)

**1. Mitigation Strategy: Filesystem-Based Detection**

*   **Description:**
    1.  **Identify Target Paths:** Create a list of *known* KernelSU-specific file and directory paths.  This is crucial: focus *only* on paths that are highly indicative of KernelSU and not generic root indicators. Examples: `/data/adb/ksu`, `/data/adb/modules`.  Avoid paths that might be present with other root solutions.
    2.  **Implement Native Checks:** Use a native library (C/C++) to perform the filesystem checks.  This is essential because KernelSU operates at the kernel level and can hook Java APIs. The native code should use system calls like `stat` or `access`.
    3.  **Handle Errors Gracefully:** Implement robust error handling.  The checks might fail for legitimate reasons.
    4.  **Infrequent Checks:** Perform these checks infrequently to minimize performance impact.
    5.  **Randomize Check Order:** Randomize the order of path checks.
    6.  **Obfuscate Path Strings:** Store the target paths in an obfuscated form.

*   **Threats Mitigated:**
    *   **Threat:** Basic KernelSU Installation Detection (Severity: Medium). Detects a standard, unmodified KernelSU installation. This is the *primary* threat this strategy addresses.
    *   **Threat:** Malicious Module Loading (Severity: High). Detects the presence of the KernelSU `modules` directory.

*   **Impact:**
    *   Basic KernelSU Installation Detection: Risk reduced by ~30%. Easily bypassed, but catches unsophisticated attempts.  The impact is *specifically* on detecting KernelSU itself.
    *   Malicious Module Loading: Risk reduced by ~20%. Detects the *potential* for KernelSU-specific modules.

*   **Currently Implemented:**
    *   Partial implementation in `SecurityUtils.java` (using Java's `File` class - **INSECURE**).
    *   Basic path checks are present, but they are not obfuscated, are performed too frequently, and include non-KernelSU-specific paths.

*   **Missing Implementation:**
    *   Native library implementation.
    *   Obfuscation of target paths.
    *   Infrequent and randomized check execution.
    *   Robust error handling.
    *   Focus on *exclusively* KernelSU-specific paths.
    *   Missing implementation in all activities that handle sensitive data.

## Mitigation Strategy: [Process-Based Detection](./mitigation_strategies/process-based_detection.md)

**2. Mitigation Strategy: Process-Based Detection**

*   **Description:**
    1.  **Native Library Implementation:** Use a native library (C/C++) to interact with the system's process listing.
    2.  **`ps` Command Execution:** Execute the `ps` command (or equivalent system calls) to retrieve a list of running processes.
    3.  **Output Parsing:** Parse the output, looking *specifically* for processes with names like `ksud` or other *known* KernelSU-related daemons.  Avoid generic root process checks.
    4.  **Blacklist:** Maintain a blacklist of *known* KernelSU-related processes. This blacklist must be kept up-to-date.
    5.  **Regular Expression Matching:** Use regular expressions, but be aware of potential evasion.
    6.  **Infrequent Execution:** Perform checks infrequently.
    7.  **Asynchronous Execution:** Run checks in a background thread.

*   **Threats Mitigated:**
    *   **Threat:** KernelSU Daemon Detection (Severity: High). *Directly* detects the `ksud` daemon, a strong indicator of KernelSU. This is the *key* threat mitigated.
    *   **Threat:** Malicious Module Execution (Severity: High). Indirectly mitigates by detecting suspicious processes *known* to be associated with KernelSU modules.

*   **Impact:**
    *   KernelSU Daemon Detection: Risk reduced by ~60%. More reliable than filesystem checks, but still bypassable. The impact is *specifically* on detecting the active KernelSU daemon.
    *   Malicious Module Execution: Risk reduced by ~30%. Indirect detection, relying on a *known* blacklist of KernelSU-related processes.

*   **Currently Implemented:**
    *   No implementation.

*   **Missing Implementation:**
    *   Completely missing. Requires native library implementation.
    *   Missing in all parts of the application.  Needs a focused blacklist of KernelSU processes.

## Mitigation Strategy: [Kernel Command Line Inspection](./mitigation_strategies/kernel_command_line_inspection.md)

**3. Mitigation Strategy: Kernel Command Line Inspection**

*   **Description:**
    1.  **Native Library Access:** Use a native library (C/C++) to read `/proc/cmdline`.
    2.  **String Parsing:** Parse the string from `/proc/cmdline`.
    3.  **Keyword Search:** Search for *specific* keywords or patterns *uniquely* associated with KernelSU, such as `ksu`. Avoid generic security-disabling parameters.
    4.  **Regular Expressions:** Use regular expressions.
    5.  **Infrequent Checks:** Perform this check sparingly.

*   **Threats Mitigated:**
    *   **Threat:** KernelSU Boot Parameter Detection (Severity: Medium). Detects if KernelSU was enabled via boot parameters. This is the *primary* and *direct* threat.

*   **Impact:**
    *   KernelSU Boot Parameter Detection: Risk reduced by ~40%. Can be bypassed, but directly targets a KernelSU-specific configuration method.

*   **Currently Implemented:**
    *   No implementation.

*   **Missing Implementation:**
    *   Completely missing. Requires native library implementation.
    *   Missing in all parts of the application. Must focus *only* on KernelSU-specific boot parameters.

