### Vulnerability List for Database Client VSCode Extension

* Vulnerability Name: SSH Tunnel Host Command Injection
* Description:
    1. An attacker can control the `host` parameter in the SSH tunnel configuration.
    2. The `sshConfig` is passed to `sshConnection.connect(config)` in `/code/src/service/ssh/forward/tunnel.js` and `/code/src/service/tunnel/tunnel-ssh.js`.
    3. The `ssh2` library might be vulnerable to command injection if the `host` parameter is not properly sanitized, especially when using "native" SSH type.
    4. An attacker could craft a malicious host string that, when processed by the underlying SSH client, executes arbitrary commands on the system where the VSCode extension is running.
* Impact:
    - **Critical:** Remote Code Execution (RCE). An attacker could execute arbitrary commands on the machine running the VSCode extension, potentially gaining full control of the system.
* Vulnerability Rank: Critical
* Currently Implemented Mitigations:
    - None identified in the provided code. The code directly uses the user-provided `host` in the `ssh2.Connection().connect(config)` call without any sanitization.
* Missing Mitigations:
    - Input sanitization for the `host` parameter in SSH tunnel configuration to prevent command injection.
    - Consider using safer methods for executing SSH commands if possible, or carefully validate all input passed to the `ssh2` library.
* Preconditions:
    - The attacker must be able to configure an SSH connection in the Database Client extension.
    - The extension must be configured to use SSH tunneling.
    - The attacker needs to be able to manipulate the SSH connection settings, specifically the `host` field.
* Source Code Analysis:
    - File: `/code/src/service/tunnel/tunnel-ssh.js`
    ```javascript
    sshConnection.connect(config);
    ```
    - File: `/code/src/service/ssh/forward/tunnel.js`
    ```javascript
    sshConnection.connect(config);
    ```
    - File: `/code/src/service/ssh/forward/tunnel.js` - `getId` function uses host and port in ID, potentially vulnerable if used unsafely later.
    ```javascript
    function getId(config) {
        return `${config.host}_${config.port}_${config.localHost}_${config.localPort}_${config.remoteHost}_${config.remotePort}`;
    }
    ```
    - Visualization:
    ```mermaid
    graph LR
        A[User Input: Malicious Host String] --> B(SSH Tunnel Config);
        B --> C{sshConnection.connect(config)};
        C --> D[ssh2 Library];
        D --> E{System Command Execution};
        E --> F[Remote Code Execution];
    ```
* Security Test Case:
    1. Open VSCode and install the Database Client extension.
    2. Open the Database Explorer panel.
    3. Click the '+' button to add a new connection.
    4. Select any database type that supports SSH tunneling (e.g., MySQL, PostgreSQL).
    5. Configure the connection to use SSH Tunnel.
    6. In the SSH configuration, enter a malicious payload in the "host" field. For example: ``127.0.0.1 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null; touch /tmp/pwned ``
    7. Fill in other required SSH connection details (username, password or private key, etc.).
    8. Attempt to connect to the database using the configured SSH tunnel.
    9. Check if the command `touch /tmp/pwned` was executed on the system running VSCode. If the file `/tmp/pwned` is created, it confirms the command injection vulnerability.

---
### Vulnerability List End