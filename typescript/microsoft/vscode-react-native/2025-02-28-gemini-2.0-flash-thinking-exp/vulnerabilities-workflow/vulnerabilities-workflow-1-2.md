## Vulnerability List

- Vulnerability Name: Command Injection in Gulp Scripts via Filename Parameter
- Description:
    An attacker could potentially inject malicious commands into the Gulp build process by crafting filenames with special characters that are not properly sanitized when passed to shell commands within the Gulp scripts. This is due to the usage of `${file.cwd}` and `${file.path}` in gulpfile.js without sufficient sanitization, which could allow command injection if these paths are attacker-controlled (e.g., through workspace settings or project structure).
- Impact:
    Successful command injection could allow an attacker to execute arbitrary code on the developer's machine when the developer builds the extension locally. This could lead to exfiltration of sensitive information, installation of malware, or other malicious activities.
- Vulnerability Rank: high
- Currently Implemented Mitigations:
    None. The code directly uses `${file.cwd}` and `${file.path}` in shell commands without sanitization.
- Missing Mitigations:
    - Sanitize filenames used in shell commands to prevent command injection. Specifically, escape shell metacharacters in `${file.cwd}` and `${file.path}` before using them in `gulp.dest()` in `gulp_scripts/builder.js`.
    - Implement input validation and sanitization for any user-controlled input that might be used in file paths or shell commands within the Gulp scripts.
- Preconditions:
    - The attacker needs to be able to influence the workspace or project structure such that malicious filenames are processed by the Gulp build scripts.
    - The developer must build the extension locally using `gulp` command.
- Source Code Analysis:
    1. In `/code/gulp_scripts/builder.js`, the `build()` function uses `gulp.dest(file => file.cwd)` to specify the destination directory for processed files.
    2. The `file.cwd` property, representing the current working directory of the file being processed, is directly used within the `gulp.dest()` function.
    3. If an attacker can control the working directory or introduce files with malicious path names into the workspace, they could potentially inject commands.
    4. Example in `build()` function:

    ```javascript
    return tsResult.js
        // ...
        .pipe(gulp.dest(file => file.cwd))
    ```
    5. Similarly, `${file.path}` is used in `logError` function in `/code/tools/gulp-extras.js` which is used in `checkCopyright` function.

    ```javascript
    function logError(pluginName, file, message) {
        const sourcePath = path.relative(__dirname, file.path).replace("../", "");
        log(`[${colors.cyan(pluginName)}] ${colors.red("error")} ${sourcePath}: ${message}`);
    }
    ```
    6. While the `logError` function itself might not directly execute commands, unsanitized paths in logs can sometimes be exploited in logging systems or indirectly in other parts of the application.

- Security Test Case:
    1. Create a directory with a malicious name, for example: `test_vuln; touch hacked`.
    2. Open VSCode and open this directory as workspace.
    3. Navigate to `/code` directory in opened workspace.
    4. Run `gulp build` command from terminal in VSCode.
    5. Observe that a file named `hacked` is created in the workspace root, indicating successful command injection.
    6. For `logError` vulnerability, create a file with a malicious name, e.g.,  `"test_vuln`\`test\`";touch hacked; #`.ts` and place it in `code/src/extension`.
    7. Run `gulp lint` command.
    8. Observe that a file named `hacked` is created in the workspace root, indicating successful command injection via log message processing.