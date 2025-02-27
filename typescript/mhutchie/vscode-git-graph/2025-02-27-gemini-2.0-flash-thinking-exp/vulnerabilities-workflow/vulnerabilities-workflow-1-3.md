- Vulnerability name: Command Injection via Git Credential Helper Arguments

- Description:
    1. The Git Graph extension uses `askpass.sh` and `askpass-empty.sh` scripts as Git credential helpers when interacting with remote repositories requiring authentication.
    2. The `askpass.sh` script executes a Node.js script (`askpassMain.js`, path specified by `VSCODE_GIT_GRAPH_ASKPASS_NODE` and main script by `VSCODE_GIT_GRAPH_ASKPASS_MAIN` environment variables) passing arguments `$*` directly to it.
    3. If a malicious Git repository is configured or a crafted Git command is executed such that it passes malicious arguments to the credential helper, these arguments are passed unsanitized to the Node.js script executed by `askpass.sh`.
    4. The `askpassMain.js` script receives these arguments and forwards the 2nd and 4th arguments as `request` and `host` values within a JSON payload via HTTP POST to the Git Graph extension's backend process.
    5. The `AskpassManager::onRequest` function in the extension's backend receives this HTTP request, parses the JSON payload, and uses the `request` and `host` values directly as `placeHolder` and `prompt` options in `vscode.window.showInputBox`.
    6. While `vscode.window.showInputBox` itself is not directly vulnerable, the unsanitized `request` and `host` values originate from potentially malicious Git configurations or commands. If the Git Graph extension or Git itself subsequently uses the *response* from the `showInputBox` (which is user-provided credentials) in an unsafe manner when constructing further Git commands, it could lead to command injection.
    7. An attacker could craft a malicious Git repository or command to inject arbitrary commands via specially crafted arguments passed to the credential helper, through `askpass.sh` and `askpassMain.js`, and finally influencing the Git commands executed by the Git Graph extension after user provides credentials.
    8. This could result in arbitrary code execution within the context of the VSCode extension, potentially allowing the attacker to gain access to user data or execute system commands.

- Impact: Arbitrary code execution. Successful exploitation allows an attacker to execute arbitrary code on the user's machine with the privileges of the VSCode extension. This could lead to sensitive information disclosure, data modification, or further system compromise.

- Vulnerability rank: High

- Currently implemented mitigations: None in the provided project files. The `askpass.sh` script directly passes arguments to the Node.js script without any sanitization. The `askpassMain.js` script forwards arguments via HTTP without sanitization. The `AskpassManager::onRequest` uses these arguments in `vscode.window.showInputBox` without sanitization. The file `/code/web/settingsWidget.ts` does not contain any mitigations or introduce new vulnerabilities.

- Missing mitigations:
    - Input sanitization of arguments `$*` in `askpass.sh` before passing them to the Node.js script.
    - Robust input validation and sanitization within the Node.js script (`askpassMain.js`) before forwarding data via HTTP.
    - Input sanitization of `request` and `host` values in `AskpassManager::onRequest` before using them in `vscode.window.showInputBox`.
    - Review and sanitization of how user-provided credentials from `vscode.window.showInputBox` are used in subsequent Git commands executed by the extension to prevent command injection.

- Preconditions:
    - The Git Graph extension must be installed and active in VSCode.
    - The user must interact with a malicious Git repository or trigger a crafted Git command that necessitates Git credential prompting.
    - The malicious repository or command must be able to influence the arguments passed to the Git credential helper.
    - The Git Graph extension's backend process (`AskpassManager::onRequest`) must unsafely handle the arguments received from `askpassMain.js`.
    - The Git Graph extension or Git itself must be vulnerable to command injection via the user-provided credentials.

- Source code analysis:
    1. **File: `/code/src/askpass/askpass.sh`**:
        ```sh
        #!/bin/sh
        VSCODE_GIT_GRAPH_ASKPASS_PIPE=`mktemp`
        VSCODE_GIT_GRAPH_ASKPASS_PIPE="$VSCODE_GIT_GRAPH_ASKPASS_PIPE" "$VSCODE_GIT_GRAPH_ASKPASS_NODE" "$VSCODE_GIT_GRAPH_ASKPASS_MAIN" $*
        cat $VSCODE_GIT_GRAPH_ASKPASS_PIPE
        rm $VSCODE_GIT_GRAPH_ASKPASS_PIPE
        ```
        - The script executes the Node.js script (`askpassMain.js`) specified by environment variables, passing all arguments `$*` directly without sanitization. This is the entry point for potentially malicious arguments.

    2. **File: `/code/src/askpass/askpassMain.ts`**:
        ```typescript
        // ... imports ...
        function main(argv: string[]): void {
            if (argv.length !== 5) return fatal('Wrong number of arguments');
            if (!process.env['VSCODE_GIT_GRAPH_ASKPASS_HANDLE']) return fatal('Missing handle');
            if (!process.env['VSCODE_GIT_GRAPH_ASKPASS_PIPE']) return fatal('Missing pipe');

            const output = process.env['VSCODE_GIT_GRAPH_ASKPASS_PIPE']!;
            const socketPath = process.env['VSCODE_GIT_GRAPH_ASKPASS_HANDLE']!;

            const req = http.request({ socketPath, path: '/', method: 'POST' }, res => { /* ... */ });

            req.on('error', () => fatal('Error in request'));
            req.write(JSON.stringify({ request: argv[2], host: argv[4].substring(1, argv[4].length - 2) }));
            req.end();
        }
        main(process.argv);
        ```
        - The `askpassMain.ts` script receives arguments from `askpass.sh` via `process.argv`.
        - It extracts `argv[2]` and `argv[4].substring(1, argv[4].length - 2)` and includes them in a JSON payload as `request` and `host` respectively.
        - This JSON payload is sent via HTTP POST to the path `/` on a socket specified by `VSCODE_GIT_GRAPH_ASKPASS_HANDLE`. There is no sanitization of `argv[2]` or `argv[4]` before they are included in the JSON payload.

    3. **File: `/code/src/askpass/askpassManager.ts`**:
        ```typescript
        // ... imports ...
        export class AskpassManager extends Disposable {
            // ...
            private onRequest(req: http.IncomingMessage, res: http.ServerResponse): void {
                let reqData = '';
                req.setEncoding('utf8');
                req.on('data', (d) => reqData += d);
                req.on('end', () => {
                    let data = JSON.parse(reqData) as AskpassRequest;
                    vscode.window.showInputBox({ placeHolder: data.request, prompt: 'Git Graph: ' + data.host, password: /password/i.test(data.request), ignoreFocusOut: true }).then(result => {
                        res.writeHead(200);
                        res.end(JSON.stringify(result || ''));
                    }, () => {
                        res.writeHead(500);
                        res.end();
                    });
                });
            }
            // ...
        }
        ```
        - The `AskpassManager::onRequest` function handles the HTTP POST request from `askpassMain.js`.
        - It parses the JSON payload into `data: AskpassRequest`.
        - It uses `data.request` as the `placeHolder` and `data.host` as part of the `prompt` in `vscode.window.showInputBox`. **Crucially, these values are used without any sanitization.**
        - The user's input from the `showInputBox` is then sent back as a JSON string in the HTTP response.

    4. **Analysis of new files**:
        - After reviewing file: `/code/web/settingsWidget.ts`, no new vulnerabilities related to command injection or other critical security issues were identified that meet the inclusion criteria. This file primarily handles settings widget functionality and UI elements, and does not introduce new attack vectors or mitigations for the identified vulnerability. This file also does not contain any mitigation for the identified vulnerability.

    5. **Vulnerability Flow:** Malicious arguments injected into Git commands are passed to `askpass.sh`, then forwarded to `askpassMain.js`, and ultimately reach `AskpassManager::onRequest` in the extension backend. Here, they are used unsanitized in `vscode.window.showInputBox`. While `showInputBox` itself is not the injection point, this flow allows attacker-controlled strings to be presented to the user and potentially influence subsequent Git operations based on the *user-provided credentials*.

- Security test case:
    1. **Setup Malicious Git Repository:**
        - Create a new Git repository in a safe testing directory.
        - Initialize Git: `git init`
        - Set up a fake remote that requires authentication. For example, you can use a non-existent or private repository URL for testing purposes.
        - Configure Git to use `askpass.sh` as credential helper for testing. Set `GIT_ASKPASS` environment variable to point to the `askpass.sh` script.
        - Craft a Git command that will trigger credential prompting, such as `git fetch origin "evil'$(touch /tmp/pwned)'"` . Note the injection within the remote name.

    2. **Execute Git Command via Git Graph Extension:**
        - Open the malicious Git repository in VSCode with the Git Graph extension enabled.
        - Trigger a Git action within Git Graph that would likely require credentials for the malicious remote (e.g., try to fetch from the remote). For instance, use the "Fetch from Remote(s)..." command in Git Graph.

    3. **Observe for Command Execution:**
        - Monitor for the execution of injected commands. In the example payload `$(touch /tmp/pwned)`, check if the file `/tmp/pwned` is created after triggering the Git action in Git Graph and providing any dummy credentials in the input box.
        - Examine system logs or use process monitoring tools to detect any unexpected command executions originating from the VSCode extension process or Git processes spawned by it.

    4. **Expected Result:**
        - If the vulnerability exists and is exploitable through the credential input, the injected command (e.g., `touch /tmp/pwned`) will be executed after providing credentials (even dummy ones) in the input box presented by Git Graph. This confirms potential command injection based on how the extension and Git handle credentials and subsequent commands. Note: The injection point may not be directly in `showInputBox` but rather in how the *response* from `showInputBox` is used in later Git commands. This test case aims to demonstrate if malicious arguments passed through the credential helper mechanism can indirectly lead to command execution after user interaction with the credential prompt.