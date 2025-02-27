- Vulnerability name: SSH Tunnel Port Forwarding Vulnerability

- Description:
    1. An attacker gains unauthorized access to a database server that is intended to be protected by an SSH tunnel.
    2. The attacker needs to know the local port that the VSCode extension is using for the SSH tunnel, which, while not directly exposed, might be discoverable through local port scanning or other means if the attacker has some level of access to the user's machine or network.
    3. The attacker then connects to the exposed local port on the user's machine, bypassing the intended security of the SSH tunnel and directly accessing the database server.
    4. This is possible because the extension, when setting up port forwarding, reuses existing tunnels based on connection details (`getId` function in `/code/src/service/ssh/forward/tunnel.js`), but it doesn't properly manage or restrict access to these forwarded ports. If a tunnel is already established for a given SSH connection, any subsequent connection attempt for the same SSH configuration will reuse the existing tunnel, potentially leaving the forwarded port open even after the original VSCode session that initiated the tunnel has ended or disconnected.

- Impact:
    - High. Unauthorized database access. If an attacker can discover the locally forwarded port, they can bypass the SSH tunnel and connect directly to the database server, potentially leading to data breaches, data manipulation, or other malicious activities.

- Vulnerability rank: High

- Currently implemented mitigations:
    - None. The code reuses existing tunnels without proper access control on the forwarded ports.

- Missing mitigations:
    - Implement proper tunnel management and access control.
    - Ensure that forwarded ports are closed when the VSCode extension disconnects or is closed.
    - Consider using dynamically generated ports that are harder to predict.
    - Implement authentication or authorization checks for connections to forwarded ports.

- Preconditions:
    - User must have established an SSH tunnel to a database server using the Database Client extension.
    - Attacker must be able to discover or guess the local port used for SSH tunnel forwarding.
    - Attacker must be able to connect to the user's localhost on the discovered port.

- Source code analysis:
    1. File: `/code/src/service/ssh/forward/tunnel.js`
    2. Function `getId(config)` creates a unique identifier for SSH tunnels based on connection parameters.
    ```javascript
    function getId(config) {
        return `${config.host}_${config.port}_${config.localHost}_${config.localPort}_${config.remoteHost}_${config.remotePort}`;
    }
    ```
    3. Function `bindSSHConnection(config, netConnection)` checks for existing tunnels using `tunelMark[id]`.
    ```javascript
    function bindSSHConnection(config, netConnection) {
        let id = getId(config)
        function forward(sshConnection, netConnection) {
            if (tunelMark[id]) { // reuse existing tunnel
                forward(tunelMark[id].connection, netConnection)
                return;
            }
            // ... rest of forward logic
        }
        if (tunelMark[id]) { // reuse existing tunnel
            forward(tunelMark[id].connection, netConnection)
            return;
        }
        // ... creates new tunnel if not exists
    }
    ```
    4. The `tunelMark` object acts as a cache for tunnels. It stores active SSH connections based on the `id`.
    5. When a new connection request comes in with the same `id`, the extension reuses the existing tunnel from `tunelMark` instead of creating a new, isolated tunnel.
    6. This reuse mechanism, while intended for performance and resource optimization, inadvertently leaves the forwarded port accessible even after the original connection is closed, as the tunnel itself persists in `tunelMark` until explicitly closed or the process terminates.
    7. There's no mechanism to restrict access to the forwarded port, meaning any application or user on the same machine can connect to `localhost:localPort` and access the database through the established tunnel.

- Security test case:
    1. Precondition: Ensure you have a database server (e.g., MySQL) and a way to connect to it (e.g., using `mysql` client).
    2. In VSCode, set up an SSH connection to your database server using the Database Client extension, configuring port forwarding (e.g., forward local port 3307 to remote database port 3306). Connect to the database using the extension.
    3. Verify that you can access the database through the extension.
    4. Disconnect the database connection in the VSCode extension.
    5. Open a terminal on the same machine where VSCode is running.
    6. Attempt to connect to the database server directly using a database client (e.g., `mysql -h 127.0.0.1 -P 3307 -u <user> -p<password>`). Use the same credentials that you used for the SSH tunnel setup.
    7. Observe that you are able to connect to the database server through the forwarded port `3307`, even though the VSCode extension is disconnected. This proves that the SSH tunnel remains active and the port remains open for unauthorized access.
    8. Expected result: You should be able to connect to the database server directly through the forwarded port, even after disconnecting the extension, demonstrating the vulnerability.