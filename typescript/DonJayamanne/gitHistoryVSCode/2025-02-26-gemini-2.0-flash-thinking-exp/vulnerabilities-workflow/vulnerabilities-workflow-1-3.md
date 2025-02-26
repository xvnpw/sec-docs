### Vulnerability List

- Vulnerability Name: Git Command Injection via Search Text

- Description:
    1. The VSCode extension "Git History, Search and More" allows users to search git history using a search text input field in the webview.
    2. When a user enters a search term and submits it, the extension sends a message from the webview to the backend with the search text as payload.
    3. In the backend, specifically in `src/viewers/historyViewer.ts`, the `handleMessageFromWebview` function processes the `SearchText` command. It extracts the `searchText` from the payload and stores it in the settings.
    4. Subsequently, when fetching git history logs (e.g., via `GitService.getLogEntries`), this `searchText` is passed down to `GitArgsService.getLogArgs`.
    5. Within `GitArgsService.getLogArgs`, the `searchText` is directly incorporated into the `git log` command using the `--grep` option without proper sanitization.
    6. An attacker can inject malicious git command options or shell commands into the `searchText` field. Since the `gitCommandExecutor.exec` executes the constructed git command via `child_process.spawn`, the injected commands will be executed by the system.

- Impact:
    - **High**. Successful command injection can allow an attacker to execute arbitrary commands on the machine where the VSCode extension is running, under the privileges of the user running VSCode. This could lead to:
        - Reading sensitive files.
        - Modifying or deleting files.
        - Installing malware.
        - Potentially escalating privileges depending on the system configuration.

- Vulnerability Rank: high

- Currently Implemented Mitigations:
    - None. The code directly uses user-provided search text in the git command without any sanitization or validation.

- Missing Mitigations:
    - **Input Sanitization:** Sanitize the `searchText` input to remove or escape any characters that could be interpreted as git command options or shell commands. For example, escape shell metacharacters or disallow characters like backticks, semicolons, pipes, etc.
    - **Input Validation:** Validate the `searchText` input to ensure it conforms to expected patterns and does not contain any potentially harmful characters or command sequences.
    - **Parameterization:** If possible, use git command parameterization mechanisms to separate user-provided search terms from command options. However, `--grep` might not directly support parameterization in a way that prevents injection.
    - **Principle of Least Privilege:** While not a direct mitigation for command injection, running the git commands with the least necessary privileges can limit the impact of a successful attack. However, this is usually managed at the system level and not within the extension itself.

- Preconditions:
    - The user must have the "Git History, Search and More" extension installed and activated in VSCode.
    - The user must open a workspace that is a Git repository.
    - The attacker needs to be able to influence the `searchText` that is used when the extension executes `git log`. This is achieved through the webview search input.

- Source Code Analysis:
    1. **`src/viewers/historyViewer.ts`:**
    ```typescript
    // ...
    private handleMessageFromWebview(message: IPostMessage) {
        switch (message.cmd) {
            // ...
            case 'SearchText': {
                this.settings.searchText = message.payload as string;
                this.updateHistory();
                break;
            }
            // ...
        }
    }
    ```
    The `searchText` from the webview message payload is directly assigned to `this.settings.searchText` without any sanitization.

    2. **`src/adapter/repository/git.ts`:**
    ```typescript
    // ...
    public async getLogEntries(
        pageIndex = 0,
        pageSize = 0,
        branches: string[] = [],
        searchText = '', // searchText is passed here
        file?: vscode.Uri,
        lineNumber?: number,
        author?: string,
    ): Promise<LogEntries> {
        // ...
        const args = this.gitArgsService.getLogArgs( // searchText is passed to getLogArgs
            pageIndex,
            pageSize,
            branches,
            searchText,
            relativePath,
            lineNumber,
            author,
        );
        // ...
        const countPromise = lineNumber
            ? Promise.resolve(-1)
            : this.exec(...args.counterArgs).then(value => parseInt(value)); // Command execution
        ``;

        const itemsPromise = Promise.all([this.exec(...args.logArgs), this.loadDereferenceHashes()]).then( // Command execution
            ([output]) => {
                // ...
            },
        );
        // ...
    }
    // ...
    private async exec(...args: string[]): Promise<string> {
        const gitRootPath = this.getGitRoot();
        return this.gitCmdExecutor.exec(gitRootPath, ...args); // Command execution using gitCommandExecutor
    }
    ```
    `searchText` is passed to `getLogArgs` and then the commands constructed using arguments from `getLogArgs` are executed via `this.exec`.

    3. **`src/adapter/repository/gitArgsService.ts`:**
    ```typescript
    // ...
    public getLogArgs(
        pageIndex = 0,
        pageSize = 100,
        branches: string[] = [],
        searchText = '', // searchText received here
        relativeFilePath?: string,
        lineNumber?: number,
        author?: string,
    ): GitLogArgs {
        // ...
        const logArgs = ['log', ...authorArgs, ...lineArgs, '--full-history', LOG_FORMAT];
        const fileStatArgs = [
            'log',
            ...authorArgs,
            ...lineArgs,
            '--full-history',
            `--format=${LOG_ENTRY_SEPARATOR}${newLineFormatCode}`,
        ];
        const counterArgs = ['rev-list', ...authorArgs, '--full-history'];

        if (searchText && searchText.length > 0) {
            searchText
                .split(' ')
                .map(text => text.trim())
                .filter(text => text.length > 0)
                .forEach(text => {
                    logArgs.push(`--grep=${text}`, '-i'); // searchText is used directly in --grep
                    fileStatArgs.push(`--grep=${text}`, '-i'); // searchText is used directly in --grep
                    counterArgs.push(`--grep=${text}`, '-i'); // searchText is used directly in --grep
                });
        }
        // ...
        return { logArgs, fileStatArgs, counterArgs };
    }
    // ...
    ```
    The `searchText` is directly embedded within the `--grep` argument in `logArgs`, `fileStatArgs`, and `counterArgs` without any sanitization. This directly leads to the command injection vulnerability.

    4. **`src/server/apiController.ts`:**
    ```typescript
    // ...
    public async getLogEntries(args: any) {
        let searchText = args.searchText;
        searchText = typeof searchText === 'string' && searchText.length === 0 ? undefined : searchText;

        // ... other arguments parsing

        const entries = await this.gitService.getLogEntries(
            pageIndex,
            pageSize,
            branches,
            searchText, // searchText is passed to gitService.getLogEntries
            file,
            lineNumber,
            author,
        );
        // ...
    }
    // ...
    ```
    In `apiController.ts`, the `getLogEntries` function receives the `searchText` from the webview's request payload (`args.searchText`). It performs a basic check to treat empty strings as undefined but does not apply any sanitization or validation before passing it to `this.gitService.getLogEntries`. This confirms that the unsanitized `searchText` from the webview is directly used in subsequent git commands.

- Security Test Case:
    1. Open VSCode in a workspace that is a Git repository.
    2. Activate the "Git History: View History" command (e.g., using `F1` and typing "Git: View History"). This will open the Git History webview.
    3. In the search bar within the Git History webview, enter the following payload as the search text:
        ```
        `--author=$(touch /tmp/pwned)`
        ```
        or
        ```
        `--author=$(calc.exe)` (for Windows)
        ```
        or any other system command you want to execute.
    4. Press Enter or trigger the search.
    5. Observe the result. If the command injection is successful, a file named `pwned` should be created in the `/tmp/` directory (or calculator should open on Windows).

This test case demonstrates that arbitrary commands can be injected via the search text field and executed by the system.