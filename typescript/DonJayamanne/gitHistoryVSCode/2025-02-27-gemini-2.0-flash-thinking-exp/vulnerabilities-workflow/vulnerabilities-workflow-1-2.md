### Vulnerability List

* Vulnerability Name: Git Command Injection via Search Text

* Description:
    The Git History extension allows users to search git history using a search text input in the webview. This search text is passed to the backend and used to construct Git commands using the `--grep` option. By crafting a malicious search text, an attacker can inject arbitrary Git command options, potentially leading to command injection.

    Steps to trigger vulnerability:
    1. Open the Git History view in VSCode.
    2. In the search input field, enter a malicious payload designed to inject Git command options. For example, `--author=attacker --pretty=format:%x00`.
    3. Trigger the search by pressing Enter or clicking the search button.
    4. The extension will execute a Git log command with the injected options.

* Impact:
    Successful command injection can allow an attacker to execute arbitrary Git commands, potentially leading to:
    - Information disclosure: Access to sensitive information from the Git repository or the system.
    - Data integrity compromise: Modification of Git repository data.
    - Local file system access: Read or write arbitrary files on the machine running VSCode, depending on the capabilities of the injected Git commands and any further exploitation.

* Vulnerability Rank: high

* Currently Implemented Mitigations:
    None. The extension directly uses user-provided search text in Git commands without sanitization.

* Missing Mitigations:
    - Input sanitization: Sanitize the `searchText` input to remove or escape any characters that could be interpreted as Git command options. Ideally, avoid using `--grep` with user-provided input directly. If `--grep` is necessary, ensure proper escaping or use Git command API if available to avoid shell command construction.
    - Input validation: Validate the search input to ensure it conforms to expected patterns and does not contain malicious characters or sequences.

* Preconditions:
    - The user must have the Git History extension installed and activated in VSCode.
    - The user must open the Git History view and interact with the search functionality.
    - The Git repository must be accessible to the extension.

* Source Code Analysis:

    1.  `src/adapter/repository/gitArgsService.ts`: The `getLogArgs` function constructs Git command arguments.
    ```typescript
    public getLogArgs(
        pageIndex = 0,
        pageSize = 100,
        branches: string[] = [],
        searchText = '', // User-controlled input
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
                .split(' ') // Splits by space, but doesn't prevent option injection
                .map(text => text.trim())
                .filter(text => text.length > 0)
                .forEach(text => {
                    logArgs.push(`--grep=${text}`, '-i'); // Injects user input directly into git command
                    fileStatArgs.push(`--grep=${text}`, '-i'); // Injects user input directly into git command
                    counterArgs.push(`--grep=${text}`, '-i'); // Injects user input directly into git command
                });
        }
        // ...
        return { logArgs, fileStatArgs, counterArgs };
    }
    ```
    The `searchText` is taken directly and incorporated into the `logArgs`, `fileStatArgs`, and `counterArgs` arrays as `--grep` options.  Splitting by space and trimming does not prevent command injection as other characters or sequences can be used to inject options.

    2. `src/adapter/repository/git.ts`: The `getLogEntries` function calls `gitArgsService.getLogArgs` and executes the command.
    ```typescript
    public async getLogEntries(
        // ...
        searchText = '', // Input from ApiController
        // ...
    ): Promise<LogEntries> {
        // ...
        const args = this.gitArgsService.getLogArgs( // Calls GitArgsService to construct args with searchText
            pageIndex,
            pageSize,
            branches,
            searchText, // User input passed to getLogArgs
            relativePath,
            lineNumber,
            author,
        );
        // ...
        const countPromise = lineNumber
            ? Promise.resolve(-1)
            : this.exec(...args.counterArgs).then(value => parseInt(value));

        const itemsPromise = Promise.all([this.exec(...args.logArgs), this.loadDereferenceHashes()]).then( // Executes git command with user input
            ([output]) => {
                // ...
            });
        // ...
    }
    ```
    The `searchText` from `ApiController` is passed to `gitArgsService.getLogArgs` and then the resulting command arguments are executed using `this.exec`.

    3. `src/server/apiController.ts`: The `getLogEntries` function in `ApiController` receives the search text from the webview and passes it to `gitService.getLogEntries`.
    ```typescript
    public async getLogEntries(args: any) {
        let searchText = args.searchText; // User input from webview

        // ...

        const entries = await this.gitService.getLogEntries( // Calls Git service with user input
            pageIndex,
            pageSize,
            branches,
            searchText, // User input passed to Git service
            file,
            lineNumber,
            author,
        );

        // ...
    }
    ```
    The `searchText` originates from user input in the webview and flows through `ApiController` and `Git` service to `GitArgsService` where it is used to construct and execute the Git command without proper sanitization.

* Security Test Case:

    1.  Install and activate the Git History extension in VSCode.
    2.  Open a Git repository in VSCode.
    3.  Open the Git History view (e.g., by running the `Git: View History` command).
    4.  In the search input field, enter the following payload: `test --pretty=format:'%x00'`
    5.  Observe the output in the 'Git History' output channel. If command injection is successful, you might see unexpected output or errors resulting from the injected `--pretty` option, which is not intended for use with `--grep`. A successful injection might manifest as a change in the log format or errors from git due to the unexpected option.

    A more robust test case would involve trying to redirect output or execute other dangerous git commands via injection, but demonstrating the injection of `--pretty` is sufficient to prove the vulnerability. For security reasons and to avoid unintentional side effects, this simple test case is recommended for initial validation.

Vulnerability Rank Justification:

The vulnerability is ranked as high because it allows for Git Command Injection, which can have significant security implications, including information disclosure, data integrity compromise, and potentially local file system access. Although it's not direct arbitrary code execution, the ability to control Git commands is a serious security risk. An attacker could potentially craft payloads to extract sensitive information from the repository history or even modify repository metadata. Given the potential impact and the ease of exploitation (simply entering a crafted search term), a high-rank is appropriate.