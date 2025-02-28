## Vulnerability List

- Vulnerability Name: **Command Injection in `askpass.sh` via Unsanitized Arguments**
- Description:
    - The `askpass.sh` script is used to obtain credentials for Git operations.
    - Arguments are passed to `askpass.sh` via environment variables and command line arguments (`$*`).
    - Lack of sanitization of these arguments allows for potential command injection when `askpass.sh` executes a Node.js script using arguments.
    - An attacker could craft Git commands to inject malicious arguments into `askpass.sh`, leading to arbitrary code execution.
    - Step-by-step trigger:
        1. Attacker crafts a malicious Git command (e.g., using a crafted repository or manipulated settings).
        2. The Git Graph extension executes this command, triggering Git's credential prompting mechanism.
        3. Git calls `askpass.sh` with arguments influenced by the attacker's crafted Git command.
        4. `askpass.sh` executes a Node.js command, incorporating the unsanitized attacker-controlled arguments.
        5. Due to the lack of sanitization, the injected commands are executed by the shell, leading to potential arbitrary code execution.
- Impact:
    - High. Command injection allows arbitrary code execution on the user's machine, potentially leading to data theft, malware installation, or system compromise.
- Vulnerability Rank: High
- Currently Implemented Mitigations:
    - None in `askpass.sh`. Arguments are directly passed to the Node.js process.
- Missing Mitigations:
    - Input sanitization within `askpass.sh` is essential.  However, the mitigation should primarily be implemented in the Node.js code (`askpassMain.ts`) that processes these arguments to ensure safe handling and prevent shell injection.
- Preconditions:
    - Attacker must be able to influence Git commands executed by the Git Graph extension to trigger credential prompts.
    - Attacker must craft input that, when passed to `askpass.sh`, results in command injection.
- Source Code Analysis:
    - File: `/code/src/askpass/askpass.sh`
    ```sh
    #!/bin/sh
    VSCODE_GIT_GRAPH_ASKPASS_PIPE=`mktemp`
    VSCODE_GIT_GRAPH_ASKPASS_PIPE="$VSCODE_GIT_GRAPH_ASKPASS_PIPE" "$VSCODE_GIT_GRAPH_ASKPASS_NODE" "$VSCODE_GIT_GRAPH_ASKPASS_MAIN" $*
    cat $VSCODE_GIT_GRAPH_ASKPASS_PIPE
    rm $VSCODE_GIT_GRAPH_ASKPASS_PIPE
    ```
    - The critical line is: `VSCODE_GIT_GRAPH_ASKPASS_PIPE="$VSCODE_GIT_GRAPH_ASKPASS_PIPE" "$VSCODE_GIT_GRAPH_ASKPASS_NODE" "$VSCODE_GIT_GRAPH_ASKPASS_MAIN" $*`
    - `$*` expands to command-line arguments passed to `askpass.sh`, which are directly appended to the command executed via `sh`.
    - No sanitization is applied to `$*`, making it vulnerable to command injection if an attacker can control these arguments.
    - The environment variables `VSCODE_GIT_GRAPH_ASKPASS_NODE` and `VSCODE_GIT_GRAPH_ASKPASS_MAIN` are assumed to be controlled by the extension and are not considered attack vectors in this context.
- Security Test Case:
    - Precondition: Attacker controls a Git repository opened in VSCode with Git Graph.
    - Steps:
        1. Create a malicious Git repository.
        2. Configure the repository to require authentication (e.g., set up a dummy private remote).
        3. Create a branch with a name containing a command injection payload, e.g., `"branch-name; touch /tmp/pwned;"`.
        4. In VSCode with Git Graph extension active, open the malicious repository.
        5. Trigger a Git Graph action that may require authentication and uses the malicious branch name, such as fetching from the remote or viewing branch details.
        6. Observe if the injected command `touch /tmp/pwned` is executed by checking for the existence of `/tmp/pwned`.
    - Expected result: Creation of `/tmp/pwned` confirms command injection vulnerability.

- Vulnerability Name: **Unsafe URI handling in `DiffDocProvider` leading to potential file system access**
- Description:
    - `DiffDocProvider` uses `git-graph://` URIs to display file content in VSCode's Diff View.
    - `decodeDiffDocUri` decodes URI query parameters, including `filePath` and `repo`, from base64 encoded JSON.
    - Lack of sanitization for decoded `filePath` and `repo` in `provideTextDocumentContent` could allow path traversal attacks, potentially exposing files outside the workspace.
    - Step-by-step trigger:
        1. Attacker crafts a malicious `git-graph://` URI with a manipulated `filePath` parameter containing path traversal sequences like `../`.
        2. The attacker delivers this URI to the user (e.g., via a crafted link or within a malicious repository).
        3. The user opens the crafted URI in VSCode, activating `DiffDocProvider`.
        4. `decodeDiffDocUri` decodes the URI parameters, including the malicious `filePath`.
        5. `provideTextDocumentContent` uses the unsanitized `filePath` to call `dataSource.getCommitFile`.
        6. If `dataSource.getCommitFile` doesn't validate the path, it might access and display files outside the intended repository directory.
- Impact:
    - High. Path traversal can allow an attacker to read arbitrary files accessible to the VSCode process, potentially exposing sensitive information like source code or configuration files.
- Vulnerability Rank: High
- Currently Implemented Mitigations:
    - Base64 encoding of URI query parameters is used, but this is not a security mitigation, only an encoding method.
- Missing Mitigations:
    - Implement robust input validation and sanitization in `decodeDiffDocUri` and `provideTextDocumentContent` to prevent path traversal.
    - Verify that decoded `filePath` and `repo` values are within the expected repository context before using them in file access operations within `dataSource.getCommitFile`.
- Preconditions:
    - Attacker must be able to deliver a malicious `git-graph://` URI to the user and convince them to open it in VSCode.
- Source Code Analysis:
    - File: `/code/src/diffDocProvider.ts`
    ```typescript
    export function decodeDiffDocUri(uri: vscode.Uri): DiffDocUriData {
        return JSON.parse(Buffer.from(uri.query, 'base64').toString());
    }

    public provideTextDocumentContent(uri: vscode.Uri): string | Thenable<string> {
        const request = decodeDiffDocUri(uri);
        // ...
        return this.dataSource.getCommitFile(request.repo, request.commit, request.filePath).then( // ...
    }
    ```
    - `decodeDiffDocUri` decodes base64 query and parses it as JSON without validation.
    - `provideTextDocumentContent` directly uses `request.filePath` and `request.repo` from the decoded URI in `dataSource.getCommitFile`.
    - No checks are in place to validate if `filePath` is within the intended `repo` path, allowing path traversal.
    - File: `/code/src/dataSource.ts`
    ```typescript
    public getCommitFile(repo: string, commitHash: string, filePath: string) {
        return this._spawnGit(['show', commitHash + ':' + filePath], repo, stdout => {
            const encoding = getConfig(repo).fileEncoding;
            return decode(stdout, encodingExists(encoding) ? encoding : 'utf8');
        });
    }
    ```
    - `dataSource.getCommitFile` executes `git show` with the provided `filePath` without validation that it's within the `repo`.
- Security Test Case:
    - Precondition: Attacker can craft and deliver a malicious `git-graph://` URI.
    - Steps:
        1. Construct a malicious URI, encoding JSON in base64 for the query parameter. The JSON should include a `filePath` with path traversal sequences (e.g., `../../../sensitive-file.txt`) and a `repo` path to a legitimate repository.
        2. Example Malicious URI (Conceptual - requires correct Base64 encoding):
        `git-graph://file.txt?eyJmaWxlUGF0aCI6Ii4uLy4uLy4vc2Vuc2l0aXZlLWZpbGUudHh0IiwiY29tbWl0IjoiMWEyYjNjNGQ1ZTZmMWEyYjNjNGQ1ZTZmMWEyYjNjNGQ1ZTZmMWEyYiIsInJlcG8iOiIvpath/to/legitimate/repoIiwiZXhpc3RzIjp0cnVlfQ==`
        3. As an attacker, attempt to get a user to open this URI in VSCode, for example, by embedding it in a markdown file or tricking them into pasting it into the address bar if VSCode supports that.
        4. Observe the Diff View.
    - Expected result: If vulnerable, the Diff View might display the content of `/sensitive-file.txt` or an error indicating access to a file outside the repository, confirming the path traversal vulnerability.