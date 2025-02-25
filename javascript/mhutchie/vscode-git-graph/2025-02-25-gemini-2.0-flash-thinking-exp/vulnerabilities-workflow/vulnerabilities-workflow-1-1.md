### Vulnerability List

- Vulnerability Name: **TOCTOU vulnerability in askpass.sh leading to local file read**
- Description:
    1. The `askpass.sh` script uses `mktemp` to generate a temporary file name but does not create the file securely using `-p` option to specify a directory.
    2. The script then constructs a command to execute a Node.js script, passing the temporary file path as an argument.
    3. Before the Node.js script accesses the temporary file, a threat actor with local file system access can replace the temporary file with a symbolic link to a sensitive file (e.g., `/etc/passwd`).
    4. When the Node.js script attempts to read from the temporary file path, it will instead read the content of the file pointed to by the symbolic link (e.g., `/etc/passwd`).
    5. The `askpass.sh` script then outputs the content of this sensitive file via `cat $VSCODE_GIT_GRAPH_ASKPASS_PIPE`.
    6. This can lead to a local file read vulnerability, potentially exposing sensitive information to the threat actor.
- Impact: A threat actor can potentially read arbitrary local files on the system where the `askpass.sh` script is executed. This could lead to the disclosure of sensitive information such as configuration files, credentials, or other user data.
- Vulnerability Rank: high
- Currently Implemented Mitigations: No mitigations are implemented in the provided `askpass.sh` script.
- Missing Mitigations:
    - Securely create temporary files using `mktemp -p` to specify a secure directory for temporary file creation, mitigating TOCTOU vulnerabilities.
    - Ensure the Node.js script handles the temporary file securely and does not rely on insecure file operations based on the filename.
    - Consider alternative secure inter-process communication methods instead of temporary files for passing sensitive information.
- Preconditions:
    - The threat actor must be able to trigger a Git command within the Git Graph extension that requires authentication and invokes the `askpass.sh` script.
    - The threat actor must have local file system access to replace the temporary file created by `mktemp` with a symbolic link before it is accessed by the Node.js script. This might be possible in shared hosting environments or containerized environments where the attacker has some level of filesystem manipulation capability.
- Source Code Analysis:
    1. **`src/askpass/askpass.sh`**:
        ```sh
        #!/bin/sh
        VSCODE_GIT_GRAPH_ASKPASS_PIPE=`mktemp`
        VSCODE_GIT_GRAPH_ASKPASS_PIPE="$VSCODE_GIT_GRAPH_ASKPASS_PIPE" "$VSCODE_GIT_GRAPH_ASKPASS_NODE" "$VSCODE_GIT_GRAPH_ASKPASS_MAIN" $*
        cat $VSCODE_GIT_GRAPH_ASKPASS_PIPE
        rm $VSCODE_GIT_GRAPH_ASKPASS_PIPE
        ```
        - Line 2: `VSCODE_GIT_GRAPH_ASKPASS_PIPE=`mktemp`` - This line uses `mktemp` to generate a temporary file name. However, it does not use the `-p` option to specify a secure directory, nor does it create the file securely. This makes it vulnerable to TOCTOU attacks.
        - Line 3: `VSCODE_GIT_GRAPH_ASKPASS_PIPE="$VSCODE_GIT_GRAPH_ASKPASS_PIPE" "$VSCODE_GIT_GRAPH_ASKPASS_NODE" "$VSCODE_GIT_GRAPH_ASKPASS_MAIN" $*` - This line executes a Node.js script, passing the temporary file path as the first argument. If the Node.js script is designed to read credentials from this file based on the provided path, it becomes vulnerable if the file is replaced with a symlink.
        - Line 4: `cat $VSCODE_GIT_GRAPH_ASKPASS_PIPE` - This line reads the content of the temporary file (or the file pointed to by the symlink if a TOCTOU attack was successful) and outputs it.
        - Line 5: `rm $VSCODE_GIT_GRAPH_ASKPASS_PIPE` - This line attempts to delete the temporary file (or symlink).

        **Visualization:**

        ```
        [askpass.sh starts]
            |
            |--- mktemp -> /tmp/tmpfile.XXXXXX  (Vulnerable: Insecure temp file creation)
            |
            |--- Node.js script is executed with "/tmp/tmpfile.XXXXXX" as argument
            |
        [Attacker replaces /tmp/tmpfile.XXXXXX with symlink to /etc/passwd] (TOCTOU window)
            |
            |--- Node.js script tries to read from "/tmp/tmpfile.XXXXXX" (resolves to /etc/passwd)
            |
            |--- cat /tmp/tmpfile.XXXXXX (outputs content of /etc/passwd) (Vulnerability: Local File Read)
            |
        [askpass.sh ends]
        ```

- Security Test Case:
    1. **Prerequisites:**
        - Set up a local Git repository that requires authentication (e.g., using HTTP authentication).
        - Ensure you have write access to a temporary directory where `mktemp` typically creates files (e.g., `/tmp`).
        - You need to be able to execute commands as the user that runs the VSCode extension and `askpass.sh`.
    2. **Steps:**
        - Identify the temporary directory used by `mktemp` on your system (usually `/tmp` or `/var/tmp`).
        - Modify the `askpass.sh` script temporarily to output the generated temporary file path to a known location (e.g., a file in `/tmp/`). Add `echo "TEMP_FILE=$VSCODE_GIT_GRAPH_ASKPASS_PIPE" >> /tmp/askpass_temp_file_path.log` after line 2 in `askpass.sh`.
        - Trigger a Git command in VSCode Git Graph that will invoke the `askpass.sh` script (e.g., try to fetch from the authenticated repository).
        - Check the `/tmp/askpass_temp_file_path.log` file to get the generated temporary file path, let's say it is `/tmp/tmpfile.XXXXXX`.
        - Before the Git authentication prompt appears or shortly after triggering the Git command, in a separate terminal, replace the temporary file with a symbolic link to `/etc/passwd`: `rm /tmp/tmpfile.XXXXXX && ln -s /etc/passwd /tmp/tmpfile.XXXXXX`.
        - Enter any dummy credentials in the Git authentication prompt in VSCode Git Graph to proceed with the `askpass.sh` execution.
        - Observe the output of the Git Graph extension or check the logs. If the vulnerability is triggered, the content of `/etc/passwd` might be displayed or logged, instead of the expected authentication input.
    3. **Expected Result:** The content of `/etc/passwd` (or another targeted sensitive file) is leaked, demonstrating a local file read vulnerability due to the TOCTOU issue in `askpass.sh`.