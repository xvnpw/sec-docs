### Vulnerability List for CMake Tools

* Vulnerability Name: Command Injection in `translations_auto_pr.js`

* Description:
    1. A malicious actor identifies that the `translations_auto_pr.js` script, used for automating localization pull requests, constructs a git command by directly embedding command-line arguments like `authUser`, `authToken`, `repoOwner`, and `repoName` into a shell command.
    2. The vulnerable code is: `cp.execSync(\`git remote add origin https://${authUser}:${authToken}@github.com/${repoOwner}/${repoName}.git\`)`.
    3. By controlling the input to the script, specifically these command-line arguments, an attacker can inject arbitrary shell commands.
    4. For example, if the attacker can influence the `repoName` argument, they can inject commands after the intended repository name, leading to execution of attacker-controlled commands on the system running the script.

* Impact:
    - **High**
    - Successful command injection allows an attacker to execute arbitrary commands on the server or CI/CD pipeline where the `translations_auto_pr.js` script is executed.
    - This can lead to severe consequences, including unauthorized access to source code, modification of the build or deployment process, data exfiltration, or even complete compromise of the affected system.

* Vulnerability Rank: high

* Currently Implemented Mitigations:
    - None. The script directly concatenates command-line arguments into a shell command without any sanitization or escaping.

* Missing Mitigations:
    - **Input Sanitization:**  Implement robust input validation and sanitization for all command-line arguments (`authUser`, `authToken`, `repoOwner`, `repoName`) to prevent shell command injection. Disallow shell metacharacters and command separators.
    - **Use of `child_process.spawn` with argument array:** Instead of `cp.execSync` with string interpolation, utilize `child_process.spawn` with an array of arguments. This prevents shell interpretation of the arguments.
    - **Principle of Least Privilege:** Ensure the script runs with minimal necessary privileges to limit the impact of command injection.

* Preconditions:
    - The attacker needs to find a way to influence the command-line arguments passed to the `translations_auto_pr.js` script. While direct external access to this script in a VS Code extension context is unlikely, if the script is part of a CI/CD pipeline triggered by external events or if there are other vulnerabilities allowing indirect control of script execution parameters, this vulnerability can be exploited.

* Source Code Analysis:
    ```javascript
    cp.execSync(\`git remote add origin https://${authUser}:${authToken}@github.com/${repoOwner}/${repoName}.git\`)
    ```
    - The `cp.execSync` function executes a shell command.
    - String interpolation using backticks is used to construct the git command, embedding variables directly into the command string.
    - The variables `authUser`, `authToken`, `repoOwner`, and `repoName` are taken as input and directly placed into the command without any encoding or validation.
    - An attacker can inject shell commands by crafting a malicious payload within these input variables. For instance, setting `repoName` to  `"repository; malicious command"` would result in the execution of `malicious command` after the `git remote add` command.

* Security Test Case:
    1. Set up a controlled environment where you can execute the `translations_auto_pr.js` script. This might involve mimicking the CI/CD environment where this script is intended to run.
    2. Prepare a malicious payload for the `repoName` argument, for example:  `\`testrepo && touch injected.txt\``. This payload attempts to create a file named `injected.txt` in the current working directory after the intended git command (which will likely fail due to `testrepo` being an invalid repo name).
    3. Execute the `translations_auto_pr.js` script with this malicious `repoName` payload and dummy values for other arguments like `authUser`, `authToken`, and `repoOwner`.
    4. After the script execution, check the environment for the presence of the `injected.txt` file.
    5. If `injected.txt` is created, this confirms successful command injection, demonstrating that an attacker can execute arbitrary commands by controlling the `repoName` argument.


* Vulnerability Name: Command Injection via `${command}` variable expansion

* Description:
    1. An attacker discovers that the CMake Tools extension uses variable expansion, including the `${command:commandName}` syntax, in various configuration files like `tasks.json`, `launch.json`, and CMake settings.
    2. The `expandString` function in `/code/src/expand.ts` processes these expansions using `vscode.commands.executeCommand(command, opts.vars.workspaceFolder)`.
    3. By crafting or manipulating configuration files that are processed by `expandString`, an attacker can inject and execute arbitrary VS Code commands through the `${command:}` syntax.
    4. Although directly modifying workspace files might seem restricted, scenarios like shared workspaces, misconfigurations, or vulnerabilities in other extensions that can alter configurations could enable an attacker to inject malicious commands.

* Impact:
    - **High**
    - Successful command injection via `${command:}` allows an attacker to execute any VS Code command.
    - This grants significant control within the VS Code environment, potentially enabling:
        - **Workspace File Manipulation:** Reading, modifying, or deleting files in the workspace.
        - **Code Execution via Extensions:** Triggering commands from other installed extensions, potentially leading to further vulnerabilities or code execution.
        - **Information Disclosure:** Exfiltrating sensitive data accessible within the workspace.
        - **System Access (Potentially):** Depending on the capabilities of executed commands and installed extensions, further access to the user's system might be possible.

* Vulnerability Rank: high

* Currently Implemented Mitigations:
    - Limited mitigation exists in `preset.ts` and `presetsParser.ts` where `expandString` is sometimes called with `doNotSupportCommands: true`, disabling `${command}` expansion specifically for preset expansion.
    - However, this mitigation is not globally applied to all usages of `expandString`, leaving other areas vulnerable to command injection. The default behavior of `expandString` is to allow command execution.

* Missing Mitigations:
    - **Global Disablement of `${command}` by Default:**  The `expandString` function should default to disabling command expansion (`doNotSupportCommands: true`) unless explicitly enabled in specific, carefully reviewed contexts.
    - **Command Whitelisting:** Implement a whitelist of allowed commands for `${command}` expansion. Only pre-approved, safe commands should be executable through this mechanism.
    - **User Confirmation Prompt:** Before executing any command via `${command}` expansion, especially if originating from workspace configurations, display a confirmation prompt to the user, mitigating risks from shared or potentially compromised workspaces.

* Preconditions:
    - The attacker needs to find a way to inject or modify a configuration string that is processed by the `expandString` function within a VS Code workspace where the CMake Tools extension is active. This could involve:
        - **Shared Workspace:**  Contributing a malicious workspace configuration to a shared project.
        - **Workspace Settings Manipulation:**  Finding a way to indirectly modify workspace settings, possibly through another extension vulnerability or misconfiguration.
    - The attacker must know a valid VS Code command to inject that will achieve their malicious goal.

* Source Code Analysis:
    ```typescript
    const commandRegex = RegExp(`\\$\\{command:(${varValueRegexp})\\}`, "g");
    for (const mat of matchAll(input, commandRegex)) {
        if (opts.doNotSupportCommands) { // Mitigation exists, but is opt-in
            log.warning(localize('command.not.supported', 'Commands are not supported for string: {0}', input));
            break;
        }
        const full = mat[0];
        const command = mat[1];
        if (subs.has(full)) {
            continue;  // Don't execute commands more than once per string
        }
        try {
            expansionOccurred = true;
            const result = await vscode.commands.executeCommand(command, opts.vars.workspaceFolder); // Vulnerable line
            subs.set(full, `${result}`);
        } catch (e) {
            // ... error handling ...
        }
    }
    ```
    - The code scans the input string for patterns matching `${command:commandName}` using a regular expression.
    - When a match is found, the `commandName` is extracted.
    - `vscode.commands.executeCommand(command, opts.vars.workspaceFolder)` is directly called with the extracted `commandName`, executing it within VS Code.
    - The `opts.doNotSupportCommands` check is present, but it's an optional parameter for the caller of `expandString`, not a default security measure within the function itself.

* Security Test Case:
    1. As an attacker, create a malicious `settings.json` file within a CMake project's `.vscode` directory (or modify the user `settings.json`).
    2. In this `settings.json`, inject a `${command:}` payload into a CMake Tools setting that uses string expansion. For example, set `cmake.buildArgs` to: `["${command:workbench.action.terminal.sendNativeTextCommand?%22echo%20Vulnerable%20Command%20Executed%22}"]`. This injects the command `workbench.action.terminal.sendNativeTextCommand` to send text to the terminal. URL encoding `%22` is used to represent double quotes in the command argument.
    3. Open this CMake project in VS Code with the CMake Tools extension active. Ensure "configureOnOpen" is enabled or manually trigger CMake configuration.
    4. Observe if a new terminal window opens and executes the command `echo Vulnerable Command Executed`.
    5. If the command is executed in the terminal, this confirms the command injection vulnerability. The attacker successfully executed a VS Code command by injecting it into a configuration setting processed by `${command}` expansion.

* Vulnerability Name: Context Key Expression Parsing Vulnerability (Regex Injection)

* Description:
    1. A malicious actor analyzes the `contextKeyExpr.ts` code and discovers a flaw in the regex parsing logic within the `Scanner` class's `_regex()` method.
    2. The vulnerability lies in the incorrect handling of unescaped forward slashes `/` inside regex patterns. The parser might prematurely terminate regex tokenization or misinterpret the regex structure when encountering unescaped slashes within character classes or other regex constructs.
    3. By crafting a malicious context key expression with a regex containing unescaped forward slashes, an attacker can cause the parser to misparse the regex.
    4. This misparsing can lead to incorrect context key evaluation, potentially bypassing intended access controls or triggering unintended behavior within the VS Code extension.

* Impact:
    - **High**
    - Exploiting this regex parsing vulnerability can lead to significant impact through logic bypass in context key evaluations.
    - Maliciously crafted context key expressions can:
        - **Bypass Access Controls:** Circumvent intended restrictions on features, commands, or UI elements controlled by context keys.
        - **Trigger Unintended Behavior:** Cause the extension to behave in unexpected ways due to misinterpretation of context conditions.
        - **Logic Errors:** Introduce subtle or critical logic errors in the extension's functionality that relies on context key evaluations.

* Vulnerability Rank: high

* Currently Implemented Mitigations:
    - Error handling exists within the `_regex()` method, which adds error tokens to `_errors` and `_tokens` when parsing issues are detected.
    - However, this error handling does not fully prevent misparsing, particularly in cases with unescaped slashes. The parser may attempt error recovery (`regexParsingWithErrorRecovery` option), which can lead to accepting and misinterpreting invalid regexes rather than rejecting them.

* Missing Mitigations:
    - **Robust Regex Parsing:** Replace the manual character-by-character regex parsing in `_regex()` with a proper, established regex parser library or a significantly more robust and rigorously tested parsing implementation. This is crucial for correct handling of complex regex syntax, escape sequences, and edge cases.
    - **Strict Input Validation:** Implement strict validation of regex syntax during parsing. The parser should reject context key expressions containing invalid or ambiguous regex patterns, especially those with unescaped forward slashes in problematic contexts.
    - **Security Review of Context Key Logic:** Thoroughly review all uses of context keys within the extension to assess the potential security consequences of misparsed regexes and ensure context key evaluations are not the sole basis for critical security decisions.

* Preconditions:
    - The attacker needs to be able to inject or influence a context key expression string that will be parsed by the `Parser` class in `contextKeyExpr.ts`. This could be achieved by:
        - **Manipulating `package.json`:** Modifying `when` clauses in the extension's `package.json` file if an attacker can somehow influence the extension's build or packaging process (less likely for external attacker).
        - **Indirect Configuration Injection:** Finding a way to inject malicious context key expressions into settings or other configuration files that are processed by the context key parser.
        - **Exploiting other Extension Vulnerabilities:** Chaining this regex parsing vulnerability with other vulnerabilities that allow control over context key expressions.

* Source Code Analysis:
    ```typescript
    private _regex() {
        // ... (code snippet from previous response) ...
    }
    ```
    - The `_regex()` function attempts to parse regex literals.
    - It iterates character by character, but its logic for detecting the end of the regex and handling escape sequences is flawed, especially with unescaped forward slashes `/`.
    - The code incorrectly assumes that any unescaped `/` not in a character class marks the end of the regex, leading to misparsing when unescaped slashes are intended to be part of the regex pattern (e.g., when matching pathnames containing slashes).
    - The `regexParsingWithErrorRecovery` option might exacerbate the issue by attempting to recover from parsing errors in a way that leads to misinterpretation of the malicious regex rather than outright rejection.

* Security Test Case:
    1. As an attacker, create a malicious workspace or user setting that utilizes a context key expression with a regex containing unescaped forward slashes. For instance, in `settings.json`, set a setting like: `"cmake.test.contextKeyRegex": "${when: resourceFileName =~ /src/file/name.txt/ }"`.
    2. Open a workspace in VS Code with the CMake Tools extension active and this malicious setting.
    3. Open a file that should *not* match the *intended* regex (e.g., a file named `src/filename.txt`). The intended regex is likely to match filenames containing `/src/file/name.txt/`.
    4. Observe the behavior of the extension or VS Code features that are controlled by this context key (`cmake.test.contextKeyRegex`).
    5. If the feature or setting controlled by the context key is unexpectedly activated (even though `src/filename.txt` should not match `/src/file/name.txt/`), this indicates a misparsing vulnerability. The regex parser likely stopped parsing at the first unescaped `/` within the intended regex, leading to an incorrect regex and thus incorrect context evaluation.

* Vulnerability Name: Potential Regex Injection in `evaluateCondition` function

* Description:
    1. An attacker identifies that the `evaluateCondition` function in `/code/src/presets/preset.ts` evaluates conditions in CMakePresets.json, including `matches` and `notMatches` types that use regular expressions.
    2. The vulnerable code constructs a `RegExp` object directly from the `regex` property in CMakePresets.json: `const regex = new RegExp(condition.regex!)`.
    3. If an attacker can provide a malicious CMakePresets.json file (e.g., in a shared workspace), they can inject a regex payload via the `condition.regex` property.
    4. While direct command execution is unlikely, a malicious regex can lead to:
        - **Regex Denial of Service (ReDoS):** Injecting a computationally expensive regex that causes the extension to become unresponsive when evaluating presets.
        - **Logic Bypass:** Crafting a regex that always evaluates to true or false regardless of the input string, potentially bypassing intended context-based behavior or access controls within the extension based on preset conditions.

* Impact:
    - **High**
    - Regex injection in `evaluateCondition` can lead to both Denial of Service and Logic Bypass:
        - **Denial of Service (ReDoS):** A carefully crafted regex can consume excessive CPU time during evaluation, making the extension unresponsive and hindering user experience.
        - **Logic Bypass:** A malicious regex can be designed to always match or never match, overriding the intended logic of preset conditions. This can lead to unexpected behavior, feature activation/deactivation bypass, or even security-relevant logic flaws if preset conditions control access or functionality.

* Vulnerability Rank: high

* Currently Implemented Mitigations:
    - None. The code directly uses the `condition.regex` string from CMakePresets.json to create a `RegExp` object without any validation, sanitization, or complexity checks.

* Missing Mitigations:
    - **Regex Input Validation and Complexity Limits:** Implement robust validation of the `condition.regex` string before creating a `RegExp` object. This should include:
        - **Regex Complexity Analysis:** Analyze the regex string to detect and reject overly complex patterns that are prone to ReDoS. This could involve limiting regex length, nesting depth, or using static analysis tools to assess regex safety.
        - **Regex Syntax Validation:** Validate that the provided regex string is valid according to expected regex syntax rules.
    - **Sandboxed Regex Evaluation (Resource Limits):** If feasible, evaluate regexes within a sandboxed environment or with resource limits (e.g., time limits for regex execution) to mitigate ReDoS impact.
    - **Security Review of Preset Condition Logic:** Conduct a thorough security review of all code paths that rely on preset conditions, especially those using `matches` and `notMatches`, to understand the potential security implications of logic bypass or ReDoS attacks through regex injection.

* Preconditions:
    - The attacker needs to provide a malicious CMakePresets.json file within a workspace opened in VS Code with the CMake Tools extension.
    - The malicious CMakePresets.json must contain a configure preset (or other preset type) with a `condition` of type `matches` or `notMatches` that includes a malicious regex in the `regex` property.
    - The extension must process and evaluate this CMakePresets.json file, triggering the `evaluateCondition` function for the malicious preset.

* Source Code Analysis:
    ```typescript
    function evaluateCondition(condition: Condition): boolean {
        // ...
        switch (condition.type) {
            // ...
            case 'matches':
            case 'notMatches':
                validateConditionProperty(condition, 'string');
                validateConditionProperty(condition, 'regex');
                const regex = new RegExp(condition.regex!); // Vulnerable line
                const matches = regex.test(condition.string!);
                return condition.type === 'matches' ? matches : !matches;
            // ...
        }
    }
    ```
    - The `evaluateCondition` function handles `matches` and `notMatches` condition types.
    - It retrieves the `regex` string directly from the `condition` object in CMakePresets.json.
    - `new RegExp(condition.regex!)` creates a regular expression object without any input validation or sanitization of the `regex` string.
    - This allows an attacker to inject arbitrary regex patterns, leading to potential ReDoS or logic bypass when the regex is evaluated using `regex.test(condition.string!)`.

* Security Test Case:
    1. As an attacker, create a malicious CMakePresets.json file in the root of a CMake project.
    2. In this CMakePresets.json, define a configure preset with a `matches` condition that includes a ReDoS-vulnerable regex. For example:
    ```json
    {
      "version": 8,
      "configurePresets": [
        {
          "name": "redos-preset",
          "displayName": "ReDoS Test Preset",
          "description": "Preset to test ReDoS vulnerability",
          "condition": {
            "type": "matches",
            "string": "aaaaaaaaaaaaaaaaaaaaaaaaaaaa!", // Input string to trigger ReDoS
            "regex": "^(a+)+$" // ReDoS regex
          }
        }
      ]
    }
    ```
    3. Open this CMake project in VS Code with the CMake Tools extension active.
    4. Select the "redos-preset" configure preset. This action should trigger the evaluation of the malicious regex condition in `evaluateCondition`.
    5. Observe the performance of VS Code. If selecting the preset or performing subsequent CMake operations (like configure) causes VS Code to become unresponsive, freeze, or consume excessive CPU resources for an extended period, this indicates a successful ReDoS attack. Measure the time taken for preset selection with and without the malicious preset to quantify the performance degradation and confirm the ReDoS vulnerability.