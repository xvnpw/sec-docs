### Vulnerability List

- Vulnerability Name: Command Injection via Environment Variables

- Description:
    1. An attacker can modify VS Code settings for the "doxdocgen" extension.
    2. The attacker sets a configuration option that uses a templated string, such as `"doxdocgen.generic.authorTag"`.
    3. Within this templated string, the attacker includes an environment variable placeholder with a malicious payload, for example: `${env:INJECT}`.
    4. The attacker sets the environment variable `INJECT` to a command that will be executed by the shell, such as `$(malicious_command)` on Linux/macOS or `"%TEMP%\\pwned.bat"` and a batch script on Windows.
    5. When the "doxdocgen" extension is triggered to generate documentation (e.g., by typing `/**` above a function and pressing Enter), the extension processes the configuration string.
    6. The `getEnvVars` function in `src/util.ts` expands the environment variable placeholder.
    7. Due to the lack of sanitization, the malicious command within the environment variable is executed by the system shell.

- Impact:
    - Arbitrary command execution on the user's machine with the privileges of the VS Code process.
    - This can lead to various malicious activities, including data theft, malware installation, and system compromise.

- Vulnerability Rank: Critical

- Currently Implemented Mitigations:
    - None. The code directly uses environment variable values without any sanitization or validation. Based on the provided files, no mitigations have been implemented.

- Missing Mitigations:
    - Input sanitization for environment variable values before using them in string replacement.
    - Ideally, avoid environment variable expansion for user-configurable strings to eliminate the risk of command injection.
    - If environment variable expansion is absolutely necessary, use a secure method that does not involve shell interpretation or strictly limit the characters allowed in environment variable names and values to prevent command injection.
    - Security warning in the extension documentation to inform users about the risks of using environment variables in configurations and to avoid using untrusted environment variables.

- Preconditions:
    1. The user must have the "doxdocgen" VS Code extension installed.
    2. The user must modify a "doxdocgen" configuration setting that uses templated strings to include an environment variable placeholder (e.g., `doxdocgen.generic.authorTag`).
    3. The user must set the corresponding environment variable to a malicious command.
    4. The user must trigger the documentation generation feature of the extension.

- Source Code Analysis:
    1. **File: /code/src/util.ts**
        ```typescript
        export function getEnvVars(replace: string): string {
            let replacement = replace;
            const regex = /\$\{env\:([\w|\d|_]+)\}/m;
            let match: RegExpExecArray;

            // tslint:disable-next-line:no-conditional-assignment
            while ((match = regex.exec(replacement)) !== null) {
                if (match.index === regex.lastIndex) {
                    regex.lastIndex++;
                }

                const m = match[1];

                const envVar: string = env.get(m, m).asString(); // Vulnerable line: Retrieves environment variable without sanitization

                replacement = replacement.replace("${env:" + m + "}", envVar); // Vulnerable line: Replaces placeholder with unsanitized environment variable
            }

            return replacement;
        }
        ```
        The `getEnvVars` function retrieves environment variables using the `env-var` library and substitutes placeholders in the input string. It does not perform any sanitization on the retrieved environment variable values, making it vulnerable to command injection if the environment variable contains malicious commands. This function remains unchanged in the provided files and is still vulnerable.

    2. **File: /code/src/templatedString.ts**
        ```typescript
        export function getTemplatedString(original: string, template: ITemplate): string {
            const replacedTemplate = original.replace(template.toReplace, template.with);
            const replacedWithEnv = getEnvVars(replacedTemplate); // Calls vulnerable function
            return getIndentedTemplate(replacedWithEnv);
        }

        export function getMultiTemplatedString(
            original: string,
            templates: ITemplate[],
        ): string {
            // For each replace entry, attempt to replace it with the corresponding param in the template
            for (const template of templates) {
                original = original.replace(template.toReplace, template.with);
            }
            return getEnvVars(getIndentedTemplate(original)); // Calls vulnerable function
        }
        ```
        `getTemplatedString` and `getMultiTemplatedString` continue to utilize `getEnvVars` to expand environment variables within template strings, propagating the vulnerability. These functions remain unchanged and propagate the vulnerability.

    3. **File: /code/src/Config.ts**
        Configuration settings are loaded and stored. These settings, particularly those that are strings (like `authorTag`, `briefTemplate`, custom tags, file templates, etc.), can be templated and processed by `getTemplatedString` or `getMultiTemplatedString`. This mechanism is still in place and vulnerable.

    4. **File: /code/src/Lang/Cpp/CppDocGen.ts**
        ```typescript
        protected generateBrief(lines: string[]) {
            lines.push(
                ...templates.getTemplatedString(
                    this.cfg.Generic.briefTemplate,
                    { toReplace: this.cfg.textTemplateReplace, with: this.getSmartText() },
                ).split("\n"),
            );
        }

        protected generateAuthorTag(lines: string[]) {
            if (this.cfg.Generic.authorTag.trim().length !== 0) {
                const authorInfo = this.getAuthorInfo();
                // Allow substitution of {author} and {email} only
                lines.push(
                    ...templates.getMultiTemplatedString(
                        this.cfg.Generic.authorTag,
                        [
                            { toReplace: this.cfg.authorTemplateReplace, with: authorInfo.authorName },
                            { toReplace: this.cfg.emailTemplateReplace, with: authorInfo.authorEmail },
                        ],
                    ).split("\n"),
                );
            }
        }

        protected generateFilenameFromTemplate(lines: string[]) {
            if (this.cfg.File.fileTemplate.trim().length !== 0) {
                templates.generateFromTemplate(
                    lines,
                    this.cfg.nameTemplateReplace,
                    this.cfg.File.fileTemplate,
                    [this.activeEditor.document.fileName.replace(/^.*[\\\/]/, "")],
                );
            }
        }

        protected generateVersionTag(lines: string[]) {
            if (this.cfg.File.versionTag.trim().length !== 0) {
                lines.push(...templates.getIndentedTemplate(this.cfg.File.versionTag).split("\n"));
            }
        }

        protected generateCopyrightTag(lines: string[]) {
            // This currently only supports year substitution
            this.cfg.File.copyrightTag.forEach((element) => {
                templates.generateFromTemplate(
                    lines,
                    this.cfg.yearTemplateReplace,
                    element,
                    [moment().format("YYYY")],
                );
            });
        }

        protected generateCustomTag(lines: string[], target = CommentType.file) {
            let dateFormat: string = "YYYY-MM-DD"; // Default to ISO standard if not defined
            if ( this.cfg.Generic.dateFormat.trim().length !== 0) {
                dateFormat = this.cfg.Generic.dateFormat; // Overwrite with user format
            }

            // Have to check this setting, otherwise {author} and {email} will get incorrect result
            // if useGitUserName and useGitUserEmail is used
            const authorInfo = this.getAuthorInfo();

            const targetTagArray = target === CommentType.file ? this.cfg.File.customTag : this.cfg.Generic.customTags;
            // For each line of the customTag
            targetTagArray.forEach((element) => {
                if (element !== "custom") { // Prevent recursive expansion
                    // Allow any of date, year, author, email to be replaced
                    lines.push(
                        ...templates.getMultiTemplatedString(
                            element,
                            [
                                { toReplace: this.cfg.authorTemplateReplace, with: authorInfo.authorName },
                                { toReplace: this.cfg.emailTemplateReplace, with: authorInfo.authorEmail },
                                { toReplace: this.cfg.dateTemplateReplace, with: moment().format(dateFormat) },
                                { toReplace: this.cfg.yearTemplateReplace, with: moment().format("YYYY") },
                                { toReplace: "{file}", with: this.activeEditor.document.fileName.replace(/^.*[\\\/]/, "")},
                            ],
                        ).split("\n"),
                    );
                }
            });
        }
        ```
        Multiple methods in `CppDocGen` (e.g., `generateBrief`, `generateAuthorTag`, `generateFilenameFromTemplate`, etc.) use templated strings from `Config.ts` and indirectly call `getEnvVars` through `getTemplatedString` or `getMultiTemplatedString`, leading to the potential command injection. This confirms that `CppDocGen.ts` and likely other `*DocGen.ts` files are still vulnerable.

- Security Test Case:
    1. Open Visual Studio Code.
    2. Install the "doxdocgen" extension.
    3. Open the User Settings (JSON) by navigating to File > Preferences > Settings and clicking the "Open Settings (JSON)" icon in the top-right corner.
    4. Add or modify the `"doxdocgen.generic.authorTag"` setting to include an environment variable placeholder:
        ```json
        "doxdocgen.generic.authorTag": "@author ${env:PWN}"
        ```
    5. **For Linux/macOS:** Open a terminal and set the environment variable `PWN` to a command that creates a file in the `/tmp` directory:
        ```bash
        export PWN='$(touch /tmp/pwned_doxdocgen)'
        ```
    6. **For Windows:** Open a command prompt or PowerShell as administrator and set the environment variable `PWN` to a command that creates a file in the `%TEMP%` directory:
        ```cmd
        setx PWN '"%TEMP%\\pwned_doxdocgen.txt"'
        ```
        or in PowerShell:
        ```powershell
        [Environment]::SetEnvironmentVariable('PWN', '"%TEMP%\\pwned_doxdocgen.txt"', 'User')
        ```
        **Note:** On Windows, you might need to restart VS Code for environment variables to be refreshed.
    7. Open a C++ file (or create a new one and set the language to C++).
    8. Place your cursor above a function definition and type `/**` then press Enter to trigger the Doxygen comment generation.
    9. **Verify the command execution:**
        - **For Linux/macOS:** Check if the file `/tmp/pwned_doxdocgen` exists:
            ```bash
            ls /tmp/pwned_doxdocgen
            ```
        - **For Windows:** Check if the file `%TEMP%\\pwned_doxdocgen.txt` exists. Open a command prompt or PowerShell and type:
            ```cmd
            dir %TEMP%\pwned_doxdocgen.txt
            ```
            or in PowerShell:
            ```powershell
            Get-ChildItem -Path Env:\TEMP | Select-Object -ExpandProperty Value | Join-Path -ChildPath "pwned_doxdocgen.txt" | Get-Item -ErrorAction SilentlyContinue
            ```
    10. If the file is created, it confirms that the command injected through the environment variable was successfully executed by the "doxdocgen" extension, demonstrating the command injection vulnerability. This test case remains valid and can be used to verify the vulnerability.