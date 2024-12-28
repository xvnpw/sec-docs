*   **Malicious Asset Loading**
    *   **Description:** The application loads external assets like images, audio, and fonts. If these assets are maliciously crafted, they can exploit vulnerabilities in the underlying decoding libraries.
    *   **How Korge Contributes to the Attack Surface:** Korge provides functions and mechanisms for loading various asset types (e.g., `resourcesVfs["path/to/image.png"].readBitmap()`). If the source of these assets is untrusted or user-controlled, it introduces risk.
    *   **Example:** An attacker provides a specially crafted PNG file that exploits a buffer overflow vulnerability in the image decoding library used by Korge, potentially leading to a crash or even code execution.
    *   **Impact:** Denial of Service (crash), potential Remote Code Execution (RCE).
    *   **Risk Severity:** High to Critical (depending on the vulnerability).
    *   **Mitigation Strategies:**
        *   **Developers:**
            *   Validate and sanitize asset sources. Load assets only from trusted locations.
            *   Keep Korge and its dependencies (especially image/audio decoding libraries) up to date to patch known vulnerabilities.
            *   Consider using sandboxing or isolated processes for asset loading.

*   **Korge Scripting (KScript) Execution**
    *   **Description:** Korge allows the execution of KScript code. If the application allows users to provide or influence the executed KScript, it can lead to arbitrary code execution.
    *   **How Korge Contributes to the Attack Surface:** Korge provides functionalities to execute KScript code (e.g., through `Korge.runScript()`). If the source of the script is untrusted or user-controlled, it's a direct path to executing arbitrary code.
    *   **Example:** An attacker provides a malicious KScript that is executed by the application. This script could read local files, execute system commands, or establish a network connection to a remote server.
    *   **Impact:** Critical - Remote Code Execution (RCE), complete compromise of the application and potentially the user's system.
    *   **Risk Severity:** Critical.
    *   **Mitigation Strategies:**
        *   **Developers:**
            *   **Avoid allowing execution of untrusted KScript code.** If necessary, implement a robust and secure sandboxing environment for KScript execution with strict limitations on accessible APIs and resources.
            *   Carefully validate and sanitize any user-provided input that influences script execution.
            *   Principle of least privilege: Only grant the necessary permissions to the scripting environment.