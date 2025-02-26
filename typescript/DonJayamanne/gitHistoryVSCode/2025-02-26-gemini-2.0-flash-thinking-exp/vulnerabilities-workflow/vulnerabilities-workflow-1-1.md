### Vulnerability List

- Vulnerability Name: **Command Injection via Git Object Name in `getObjectHashArgs`**
- Description:
    - The `getObjectHashArgs` function in `GitArgsService` constructs Git commands using user-controlled input (`object`) without sufficient sanitization.
    - An attacker could potentially inject malicious commands by crafting a Git object name that contains shell metacharacters.
    - This could lead to arbitrary command execution on the user's system when the extension attempts to retrieve the hash of the crafted object.

- Impact:
    - **Critical**
    - Arbitrary command execution on the user's machine with the privileges of the VS Code process.
    - Attackers could potentially steal sensitive information, install malware, or compromise the user's system.

- Vulnerability Rank: critical

- Currently Implemented Mitigations:
    - None. The code directly uses the `object` parameter in the `git show` command.

- Missing Mitigations:
    - Input sanitization for the `object` parameter in `getObjectHashArgs` to prevent shell injection.
    - Ideally, avoid using shell commands for operations where a safer API or method exists. In this case, validating the `object` parameter to ensure it is a valid Git object name and does not contain shell metacharacters.

- Preconditions:
    - The user must open the Git History viewer in VSCode.
    - The attacker needs to be able to send a crafted message to the VSCode extension's webview, triggering the `getCommit` command in `ApiController` with a malicious commit hash. This could potentially be achieved through a crafted workspace or by exploiting a vulnerability in VSCode's webview messaging system itself (though less likely for an external attacker). For the purpose of this analysis, we assume the attacker can somehow influence the `hash` parameter sent to the `getCommit` API endpoint.

- Source Code Analysis:
    - File: `/code/src/adapter/repository/gitArgsService.ts`
    ```typescript
    export class GitArgsService implements IGitArgsService {
        // ...
        public getObjectHashArgs(object: string): string[] {
            return ['show', `--format=${Helpers.GetCommitInfoFormatCode(CommitInfo.FullHash)}`, '--shortstat', object];
        }
        // ...
    }
    ```
    - The `getObjectHashArgs` function takes `object: string` as input. This `object` string is directly incorporated into the command arguments for `git show`.
    - If the `object` string contains shell metacharacters (e.g., `;`, `|`, `&`, `$()`, ``), Git might interpret these as command separators or expansions, leading to command injection.
    - For example, if an attacker can control the `object` parameter and sets it to `"commit-hash; malicious-command"`, the executed command could become `git show --format=%H --shortstat commit-hash; malicious-command`. Git might execute `malicious-command` after the `git show` command.

    - File: `/code/src/server/apiController.ts`
    ```typescript
    export class ApiController {
        // ...
        public async getCommit(args: any) {
            const hash: string = args.hash;
            // ...
            const commit = await this.gitService.getCommit(hash);
            // ...
            return commit;
        }
        private postMessageParser = async (message: IPostMessage) => {
            try {
                const result = await this[message.cmd].bind(this)(message.payload);
                this.webview.postMessage({
                    requestId: message.requestId,
                    payload: result,
                });
            } catch (ex) {
                this.applicationShell.showErrorMessage((ex as Error).message);
                this.webview.postMessage({
                    requestId: message.requestId,
                    error: ex,
                });
            }
        };
    }
    ```
    - The `ApiController` class handles messages from the webview in the `postMessageParser` method.
    - When a message with `cmd: 'getCommit'` is received, the `getCommit` method is called.
    - The `getCommit` method directly takes the `hash` from the `args` parameter (which originates from the webview message payload) and passes it to `this.gitService.getCommit(hash)`.
    - If `gitService.getCommit` internally uses `getObjectHashArgs` without sanitizing the `hash` input, a command injection vulnerability exists.

- Security Test Case:
    1. Open the Git History extension in VSCode on any Git repository.
    2. We need a way to send a crafted message to the extension's webview. For testing purposes, we can modify the extension code temporarily to send a malicious message. In a real attack scenario, the attacker would need to find a way to inject or influence messages sent to the webview.
    3. Modify the `htmlViewer.ts` or any file that sends messages to `ApiController` to send a 'getCommit' message with a malicious hash. For example, in `htmlViewer.ts`, inside `createHtmlView` function, after `new ApiController(...)`, add the following line for testing:
    ```typescript
    webviewPanel.webview.postMessage({ cmd: 'getCommit', requestId: '1', payload: { hash: 'test-commit-hash; touch /tmp/pwned' } });
    ```
    4. Reload the VSCode extension or reopen the Git History view.
    5. Observe if a file named `pwned` is created in the `/tmp/` directory.
    6. If the file `/tmp/pwned` exists, the command injection vulnerability is confirmed.

- Missing Test Case:
    - No specific test case exists to validate the sanitization of Git object names passed to `getObjectHashArgs` or any functions using it, especially when triggered via the `getCommit` API endpoint.