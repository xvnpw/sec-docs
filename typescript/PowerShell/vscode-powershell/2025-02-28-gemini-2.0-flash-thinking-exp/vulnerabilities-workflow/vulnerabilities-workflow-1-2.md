### Vulnerability List for VSCode PowerShell Extension

- Vulnerability Name: Unsafe PowerShell Executable Path Configuration

- Description:
    1. An attacker can modify the VS Code settings for the PowerShell extension, specifically the `powershell.powerShellAdditionalExePaths` setting.
    2. Within this setting, they can add a PowerShell executable path that points to a malicious executable instead of a legitimate PowerShell executable.
    3. When the VS Code PowerShell extension starts or restarts a session, it reads the `powershell.powerShellAdditionalExePaths` setting.
    4. If the attacker's malicious path is chosen (either because it's the default or the user is tricked into selecting it), the extension will execute the malicious PowerShell executable instead of the intended one.
    5. This malicious PowerShell executable can then perform arbitrary actions on the user's system with the privileges of the user running VS Code.

- Impact:
    - Critical
    - Remote Code Execution: An attacker can achieve arbitrary code execution on the user's machine.
    - Privilege Escalation: If VS Code is running with elevated privileges, the attacker's code will also run with those privileges.
    - Data Exfiltration: The attacker can access and exfiltrate sensitive data from the user's machine.
    - System Compromise: Complete compromise of the user's system is possible.

- Vulnerability Rank: critical

- Currently Implemented Mitigations:
    - None. The extension allows users to configure arbitrary executable paths without validation.

- Missing Mitigations:
    - Input Validation: The extension should validate the paths provided in `powershell.powerShellAdditionalExePaths` to ensure they are legitimate PowerShell executables and not malicious ones. This could involve checking digital signatures or verifying the path against a whitelist of trusted directories.
    - Warning to User: If an unusual or potentially unsafe PowerShell executable path is configured, the extension should display a prominent warning to the user, highlighting the security risks.
    - Restrict Configuration Scope: Consider restricting the scope of the `powershell.powerShellAdditionalExePaths` setting to workspace or folder level, preventing attackers from modifying it globally.

- Preconditions:
    - Attacker must be able to modify VS Code settings, which can be achieved through various means such as:
        - Social engineering to trick the user into manually changing the settings.
        - Exploiting other vulnerabilities in VS Code or other extensions to programmatically modify settings.
        - Compromising the user's settings file directly.

- Source Code Analysis:
    1. **File: /code/src/settings.ts**
        - The `PowerShellAdditionalExePathSettings` type and `powerShellAdditionalExePaths` setting are defined, allowing users to specify custom PowerShell executable paths.
    2. **File: /code/src/platform.ts**
        - The `PowerShellExeFinder` class reads the `powerShellAdditionalExePaths` setting to enumerate PowerShell installations.
        - The `enumerateAdditionalPowerShellInstallations` method iterates through the configured paths without performing any security checks.
        - The `PossiblePowerShellExe` class encapsulates the executable path without any validation logic.
    3. **File: /code/src/session.ts**
        - The `findPowerShell` method in `SessionManager` uses `PowerShellExeFinder` to locate PowerShell installations, including those from `powerShellAdditionalExePaths`.
        - The extension then proceeds to start a PowerShell process using the potentially attacker-controlled executable path.

- Security Test Case:
    1. **Setup:**
        - On a test machine, create a malicious PowerShell executable (e.g., `malicious.ps1`) that, when run, attempts to exfiltrate data or create a backdoor.
        - Place this malicious executable in a user-writable location (e.g., `C:\Users\Public\malicious.ps1`).
    2. **Attack Scenario:**
        - As an attacker, find a way to modify the VS Code settings (e.g., through social engineering or exploiting another vulnerability).
        - In the `settings.json` file for the PowerShell extension, add an entry to `powershell.powerShellAdditionalExePaths` that points to the malicious executable created in step 1:
            ```json
            "powershell.powerShellAdditionalExePaths": {
                "Malicious PowerShell": "C:\\Users\\Public\\malicious.ps1"
            }
            ```
        - Restart VS Code or the PowerShell extension session.
        - Open a PowerShell file in VS Code to activate the extension.
        - Use the "PowerShell: Show Session Menu" command and select "Switch to: Malicious PowerShell".
    3. **Verification:**
        - Observe that the PowerShell extension starts using the malicious executable.
        - Verify that the actions defined in the malicious PowerShell executable are executed when the extension starts or when PowerShell commands are run within VS Code.
        - For example, check if exfiltrated data is sent to an attacker-controlled server or if a backdoor is created.