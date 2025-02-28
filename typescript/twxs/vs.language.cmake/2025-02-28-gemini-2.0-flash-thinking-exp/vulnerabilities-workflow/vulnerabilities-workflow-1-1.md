### Vulnerability List

* Vulnerability Name: Command Injection via Online Help Feature
* Description:
    1. The user triggers the "CMake: Online Help" command in VSCode.
    2. The extension prompts the user to enter a search term for the CMake online documentation.
    3. The user enters a malicious search term containing shell command injection payload, for example, `$(calc)`.
    4. The extension constructs a URL based on the user-provided search term.
    5. The extension uses the `opener` npm package to open this URL in the default web browser.
    6. If the `opener` package internally uses `child_process.exec` (or a similar function that executes commands through a shell) and doesn't sanitize the URL, the shell command embedded in the URL (e.g., `calc` in `$(calc)`) will be executed.
* Impact: Arbitrary code execution. An attacker can execute arbitrary commands on the machine where VSCode is running with the privileges of the VSCode process. This can lead to data theft, malware installation, or complete system compromise.
* Vulnerability Rank: Critical
* Currently Implemented Mitigations: None. The code directly uses user input to construct URLs and passes them to the `opener` function without any sanitization.
* Missing Mitigations:
    * Input sanitization: Sanitize the user-provided search term to remove or escape shell-sensitive characters before constructing the URL. This could involve URL encoding the search term or using a more robust sanitization method to prevent command injection.
    * Use a safer method to open URLs: Instead of relying on `opener`, which might use `child_process.exec`, consider using a safer built-in VSCode API or a more secure library for opening URLs that avoids shell execution. For example, VSCode API `vscode.env.openExternal` might be a safer alternative if it doesn't involve shell execution.
* Preconditions:
    * The user must have the CMake extension for VSCode installed.
    * The user must execute the "CMake: Online Help" command.
    * The `opener` npm package must be vulnerable to command injection when handling URLs (specifically, if it uses `child_process.exec` internally).
* Source Code Analysis:
    1. **`extension.ts:148`**: The `cmake_online_help` function is called with the user-provided `result` from the input box.
    2. **`extension.ts:150-183`**: Inside `cmake_online_help`, a URL is constructed based on `cmake_help_url()` and the `search` term (which is the `result` from input box).
    3. **`extension.ts:152`**: `var opener = require("opener");` - The `opener` package is loaded.
    4. **`extension.ts:160`, `extension.ts:165`, `extension.ts:175`, `extension.ts:180`**:  The `opener()` function is called with URLs that are constructed using the unsanitized `search` input. For example: `opener(url + 'search.html?q=' + search + '&check_keywords=yes&area=default');`
    5. The `opener` package, if it uses `child_process.exec` internally and doesn't sanitize the URL, will pass the constructed URL to the shell for execution. If the `search` string contains shell command injection payload like `$(command)`, the command will be executed.

    ```mermaid
    graph LR
        A[User executes "CMake: Online Help"] --> B{Input Box shows};
        B --> C[User inputs malicious search term e.g., '$(calc)'];
        C --> D{cmake_online_help(search)};
        D --> E{Construct URL with search term};
        E --> F{opener(URL)};
        F --> G{opener uses child_process.exec?};
        G -- Yes --> H[Shell executes URL as command];
        H --> I[Command from payload executed e.g., calc.exe];
        G -- No --> J[URL opened in browser normally];
    ```

* Security Test Case:
    1. Install the "CMake for Visual Studio Code" extension in VSCode.
    2. Open any CMakeLists.txt file or create a new one and set the language mode to CMake.
    3. Press `Ctrl+Shift+P` (or `Cmd+Shift+P` on macOS) to open the command palette.
    4. Type and select "CMake: Online Help".
    5. An input box will appear at the top of VSCode. In the input box, enter the following payload: `` `$(calc)` `` (for Windows, use `` `$(start calc.exe)` ``) or `` `$(touch /tmp/pwned)` `` (for Linux/macOS). Note: backticks are used here to enclose the payload for markdown, in the actual test case, use `$(calc)`.
    6. Press Enter.
    7. **Expected Outcome (Vulnerable):**
        * On Windows, the Calculator application should open.
        * On Linux/macOS, a file named `pwned` should be created in the `/tmp/` directory.
    8. **Expected Outcome (Mitigated):**
        * The CMake online help page should open in the default web browser, and no command injection should occur. The calculator should not open, and the file `/tmp/pwned` should not be created.