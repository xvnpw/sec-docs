## Vulnerability list for VSCode PowerShell extension

* Vulnerability Name: PowerShell Extension Session File Hijacking

- Description:
    - An attacker can gain unauthorized access to a user's PowerShell session by reading session files created by the PowerShell extension.
    - These session files, located in a user-accessible directory, contain sensitive pipe names used for communication.
    - An attacker with read access to these files can hijack the session and execute arbitrary PowerShell commands.

- Impact:
    - Full control over the user's PowerShell session, leading to potential data theft and system compromise.

- Vulnerability rank: Critical

- Currently implemented mitigations:
    - None. Session files are stored in a publicly readable location without encryption or access controls.

- Missing mitigations:
    - Encrypt session files.
    - Implement access controls for session files.
    - Use more secure communication channels.
    - Validate client identity to prevent unauthorized connections.

- Preconditions:
    - Attacker gains read access to the session files directory.
    - A PowerShell session is active in VSCode.

- Source code analysis:
    - Vulnerable code in `SessionManager.ts` and `process.ts` related to session file creation and usage of pipe names.

- Security test case:
    - Attacker gains read access to session files directory.
    - Attacker script connects to extracted pipe names and executes commands in the user's PowerShell session.