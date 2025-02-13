# Attack Tree Analysis for square/leakcanary

Objective: Exfiltrate Sensitive Data or Gain Unauthorized Access (via LeakCanary)

## Attack Tree Visualization

                                     Exfiltrate Sensitive Data or Gain Unauthorized Access
                                                     (via LeakCanary)
                                                        |
                                       -----------------------------------------
                                       |                                       |
                      1. Exploit LeakCanary's  Data Exposure      2.  Manipulate LeakCanary's Behavior
                                       |                                       |
                      -----------------------------------         -----------------------------------------
                      |                 |                                       |
        1.1 Access Heap Dumps   1.2  Read  Analysis                            2.2  Disable LeakCanary
              |                 |      Results                                      |
        --------------    -----------------                            -----------------
        |    [HIGH RISK] |    |       |                                       |
1.1.1 Gain    1.1.2   1.2.1   1.2.3                                     2.2.1
Physical   Network  Social  View                                      Decompile
Access to  Access   Eng.    UI                                        and Modify
Device     to       to       (if                                        App Code
  {CRITICAL} Device   Device   exposed)                                    {CRITICAL}
(rooted/ (rooted/   [HIGH RISK]
jail-    jail-
broken)  broken)
          [HIGH RISK]

## Attack Tree Path: [1. Exploit LeakCanary's Data Exposure](./attack_tree_paths/1__exploit_leakcanary's_data_exposure.md)

*   **1.1 Access Heap Dumps:**
    *   **Description:** LeakCanary generates heap dumps when memory leaks are detected. These dumps can contain sensitive data present in the application's memory at the time of the dump.
    *   **1.1.1 Gain Physical Access to Device (rooted/jailbroken) - `[HIGH RISK]` and `{CRITICAL}`:**
        *   **Description:** An attacker gains physical possession of a developer's or tester's device that has a debug build of the application installed, and the device is rooted (Android) or jailbroken (iOS), allowing unrestricted file system access.
        *   **Attack Steps:**
            1.  Obtain the device (theft, borrowing, etc.).
            2.  Bypass any device lock screen (PIN, password, biometrics).
            3.  Use file explorer tools (available on rooted/jailbroken devices) to navigate to the application's private data directory.
            4.  Locate and copy the heap dump files (usually `.hprof` files).
            5.  Analyze the heap dump files using tools like Eclipse Memory Analyzer (MAT) or Android Studio's profiler to extract sensitive data.
        *   **Likelihood:** Low
        *   **Impact:** High
        *   **Effort:** Medium
        *   **Skill Level:** Intermediate
        *   **Detection Difficulty:** Medium
    *   **1.1.2 Network Access to Device (rooted/jailbroken) - `[HIGH RISK]`:**
        *   **Description:** An attacker gains network access to a developer's or tester's device (e.g., through malware, a compromised Wi-Fi network) that has a debug build installed and is rooted/jailbroken.
        *   **Attack Steps:**
            1.  Compromise the device via a network vulnerability or malware.
            2.  Establish a remote shell or file transfer connection.
            3.  Navigate to the application's private data directory.
            4.  Locate and download the heap dump files.
            5.  Analyze the heap dump files offline.
        *   **Likelihood:** Very Low
        *   **Impact:** High
        *   **Effort:** High
        *   **Skill Level:** Advanced
        *   **Detection Difficulty:** Hard

*   **1.2 Read Analysis Results:**
    *   **Description:** LeakCanary presents analysis results, including details about leaked objects, which might inadvertently include sensitive information.
    *   **1.2.1 Social Engineering to Device - `[HIGH RISK]`:**
        *   **Description:** An attacker uses social engineering techniques to trick a developer or tester into revealing information from the LeakCanary UI or logs.
        *   **Attack Steps:**
            1.  Impersonate a colleague, support personnel, or another trusted individual.
            2.  Contact the developer/tester (phone, email, chat).
            3.  Convince them to share screenshots of the LeakCanary UI, copy/paste log output, or describe the analysis results.
            4.  Extract sensitive information from the provided data.
        *   **Likelihood:** Medium
        *   **Impact:** Medium
        *   **Effort:** Low to Medium
        *   **Skill Level:** Intermediate
        *   **Detection Difficulty:** Very Hard
    *   **1.2.3 View UI (if exposed) - `[HIGH RISK]`:**
        *   **Description:** The LeakCanary UI is accidentally exposed to unauthorized users (e.g., a debug build is released to production, a screen recording vulnerability exists).
        *   **Attack Steps:**
            1.  Gain access to the application (e.g., install a leaked debug build).
            2.  Trigger a memory leak (if necessary).
            3.  View the LeakCanary UI and the displayed analysis results.
            4.  Extract sensitive information directly from the UI.
        *   **Likelihood:** Very Low
        *   **Impact:** Medium
        *   **Effort:** Low
        *   **Skill Level:** Novice
        *   **Detection Difficulty:** Hard

## Attack Tree Path: [2. Manipulate LeakCanary's Behavior](./attack_tree_paths/2__manipulate_leakcanary's_behavior.md)

*   **2.2 Disable LeakCanary:**
    *   **Description:** An attacker attempts to disable LeakCanary to prevent it from detecting their malicious activities that would otherwise be flagged as memory leaks.
    *   **2.2.1 Decompile and Modify App Code - `{CRITICAL}`:**
        *   **Description:** An attacker decompiles the application's code, removes or modifies the LeakCanary initialization and usage, and then repackages the application.
        *   **Attack Steps:**
            1.  Obtain the application's APK (Android) or IPA (iOS) file.
            2.  Use decompilation tools (e.g., `apktool`, `dex2jar`, `jd-gui` for Android; `class-dump` for iOS) to extract the source code.
            3.  Identify and remove or modify the code related to LeakCanary.
            4.  Rebuild the application.
            5.  Resign the application (requires a signing key).
            6.  Distribute the modified application (e.g., through a malicious app store, phishing).
        *   **Likelihood:** Low
        *   **Impact:** High
        *   **Effort:** High
        *   **Skill Level:** Advanced
        *   **Detection Difficulty:** Hard

