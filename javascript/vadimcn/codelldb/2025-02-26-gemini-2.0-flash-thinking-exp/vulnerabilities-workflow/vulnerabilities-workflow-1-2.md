- **Vulnerability Name:** Unauthenticated RPC Server Allows Arbitrary Debug Configuration Injection

  - **Description:**
    - CodeLLDB supports launching debug sessions via an RPC server endpoint that accepts a JSON–formatted debug configuration. According to the documentation in MANUAL.md, the RPC server is started by adding an `"lldb.rpcServer"` setting. Although there is a rudimentary option to require a token, the token is optional. An external attacker who can reach the RPC endpoint (for example, if the RPC server is bound to a public interface or the token is omitted/weak) can submit a crafted debug configuration payload.
    - **Step-by-step Trigger Process:**
      1. The operator deploys a CodeLLDB instance with RPC server enabled (via the `"lldb.rpcServer"` workspace setting) without enforcing a strong token.
      2. An attacker connects (using a tool such as netcat) to the exposed RPC server’s host/port.
      3. The attacker sends a malicious JSON payload—for example, one that includes a `preRunCommands` array with a command to execute an arbitrary system command.
      4. Upon receiving the half–closed connection, the adapter processes the configuration and executes the injected commands.

  - **Impact:**
    - An attacker can force the debugger to execute arbitrary pre–launch or post–launch commands. This may lead to full remote code execution with the privileges of the debug adapter process and lead to data exfiltration, further compromise, or lateral movement.

  - **Vulnerability Rank:** Critical

  - **Currently Implemented Mitigations:**
    - The MANUAL.md documentation mentions that a token parameter may be set in the RPC server configuration to restrict access. This measure is optional and not enforced by default.

  - **Missing Mitigations:**
    - There is no mandatory access control or robust authentication mechanism on the RPC endpoint.
    - The design relies solely on an optional token—with no server–side validation seen in the source code—which leaves the endpoint vulnerable if misconfigured.
    - There is no input sanitization or further validation on the submitted debug configurations.

  - **Preconditions:**
    - The workspace settings must enable the RPC server (via `"lldb.rpcServer"`).
    - The machine running CodeLLDB must be reachable (or misconfigured to expose the RPC port publicly).
    - No token (or a weak one) is provided in the configuration.

  - **Source Code Analysis:**
    - The vulnerability is described entirely in the documentation (MANUAL.md’s “RPC Server” section) and is not countered in code.
    - There is no visible code that enforces token matching or further checks on the JSON debug configuration submitted by external clients.
    - As a result, if an RPC server instance is configured without proper restrictions, any connection can supply a debug configuration that is executed verbatim.

  - **Security Test Case:**
    1. Configure a CodeLLDB instance with an enabled RPC server in the workspace settings without supplying a token.
    2. From an external machine, open a TCP connection to the specified host and port (for example, using:
       ```
       nc <host> <port>
       ```
       ).
    3. Send a JSON payload such as:
       ```
       { "program": "/bin/ls", "preRunCommands": ["system('touch /tmp/pwned')"] }
       ```
    4. Close the connection (half–close, as described in the documentation).
    5. Verify on the host that the command was executed (for example, by checking that the file `/tmp/pwned` has been created).
    6. Document the results and capture network traces to demonstrate the arbitrary configuration injection.

- **Vulnerability Name:** Remote Debug Console Evaluation Allows Arbitrary Python Code Execution

  - **Description:**
    - CodeLLDB’s debug adapter supports evaluating expressions entered into the debug console. In several parts of the adapter (for example, in the `/py`–prefixed evaluation path), user–supplied text is compiled (in some cases via Python’s built–in `compile()`) and then executed via `eval()`. The evaluation context is built from the current debug session without sandboxing or proper input restrictions.
    - **Step-by-step Trigger Process:**
      1. The debug adapter is started in multi–session mode with a public port (via the `--port=4711` flag as described in BUILDING.md).
      2. An external attacker gains network access to this debug port.
      3. The attacker sends a debug console command beginning with the `/py` prefix containing malicious payloads—for example:
         ```
         /py __import__('os').system('touch /tmp/pwned')
         ```
      4. The adapter’s `evaluate_in_context` function compiles and then executes the payload via Python’s `eval()`, triggering the system command.

  - **Impact:**
    - Successful exploitation will result in arbitrary code execution on the host system running CodeLLDB with the same privileges as the debug adapter. This can directly lead to control of the target machine, data compromise, or opening the door for further intrusion.

  - **Vulnerability Rank:** Critical

  - **Currently Implemented Mitigations:**
    - The design of the debug console evaluation functions assumes operation in a trusted environment. No explicit sandboxing or restrictions are implemented.

  - **Missing Mitigations:**
    - There is no authentication or access control on the TCP port used for debug session communications.
    - The input provided to the debug console is passed directly to Python’s `compile()` and `eval()` functions without sanitization or safe–evaluation wrappers.
    - There is no separation of privileges between local developer–entered input and network–supplied commands.

  - **Preconditions:**
    - The debug adapter must be started with the `--port` flag (e.g. `--port=4711`) and the corresponding port must be accessible from outside the trusted host.
    - An attacker must have network connectivity to this port (e.g. due to misconfigured firewalls or deliberate exposure).
    - The adapter must be configured to run in multi-session mode where console input is evaluated using the Python evaluators.

  - **Source Code Analysis:**
    - In the file `/code/adapter/scripts/codelldb/interface.py`, the `evaluate_in_context` function uses the Python `eval()` call after compiling the code (using either the “simple” mode or as a proper Python expression).
    - The debug console supports prefixes (e.g. `/py`) that directly force Python evaluation.
    - There are no checks or sanitization routines to ensure that incoming text is benign.
    - The debug adapter may be listening on an externally accessible TCP port (as explained in BUILDING.md), meaning that an attacker could send such commands remotely.

  - **Security Test Case:**
    1. Start the CodeLLDB debug adapter using the command:
       ```
       code --open-url "vscode://vadimcn.vscode-lldb/launch/command?--multi-session --port=4711"
       ```
       and ensure that port 4711 is accessible.
    2. From a remote machine, connect to port 4711 (for example, using netcat):
       ```
       nc <target-ip> 4711
       ```
    3. Send the following debug console command:
       ```
       /py __import__('os').system('touch /tmp/pwned')
       ```
    4. Close the connection.
    5. On the host running the debug adapter, verify that the file `/tmp/pwned` exists.
    6. Record all steps—including network traces and any adapter logs—to demonstrate that arbitrary code execution was achieved.