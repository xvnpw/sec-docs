### Vulnerability List

* Vulnerability Name: Path Traversal via `mount` configuration
* Description:
    1. An attacker can exploit the `liveServer.settings.mount` configuration.
    2. The attacker needs to convince a user to set a malicious `mount` configuration in their VSCode settings. This could be through social engineering or by exploiting another vulnerability that allows configuration injection (unlikely in VSCode extensions settings).
    3. The user configures `liveServer.settings.mount` with a malicious URL path containing path traversal sequences, such as `[["/../../../../", "/"]]`.
    4. When Live Server starts, this configuration is used to map URL paths to file system directories.
    5. When an attacker requests a URL containing path traversal sequences (e.g., `http://localhost:<port>/../../../../etc/passwd`), the application, due to the insecure mount configuration, resolves the path and serves files from outside the intended workspace directory.
* Impact:
    - High: An attacker can potentially access sensitive files within the user's workspace or even system files if the workspace is set to a very high-level directory. This could lead to information disclosure, including source code, configuration files, or system credentials.
* Vulnerability Rank: High
* Currently Implemented Mitigations:
    - None: The provided code does not include any input validation or sanitization for the URL paths in the `mount` configuration.
* Missing Mitigations:
    - Input validation and sanitization of the `mountRule[0]` (URL path) in `Helper.ts` `generateParams` function.
    - The extension should ensure that the URL path in the `mount` configuration does not contain path traversal characters (like `..`) or restrict it to only allow alphanumeric characters and `/`.
    - Alternatively, the extension could disallow relative paths in `mountRule[0]` and enforce that all paths start from the root `/` and refer to paths within the workspace.
* Preconditions:
    - The user must configure the `liveServer.settings.mount` setting.
    - An attacker needs to induce the user to set a vulnerable configuration.
    - Live Server must be started with this malicious configuration.
* Source Code Analysis:
    - File: `/code/src/Helper.ts`
    - Function: `generateParams`
    ```typescript
    public static generateParams(
        rootPath: string,
        workspacePath: string,
        onTagMissedCallback?: MethodDecorator
    ) {
        // ...
        const mount = Config.getMount;
        // In live-server mountPath is reslove by `path.resolve(process.cwd(), mountRule[1])`.
        // but in vscode `process.cwd()` is the vscode extensions path.
        // The correct path should be resolve by workspacePath.
        mount.forEach((mountRule: Array<any>) => {
            if (mountRule.length === 2 && mountRule[1]) {
                mountRule[1] = path.resolve(workspacePath, mountRule[1]);
            }
        });
        // ...
        return {
            // ...
            mount: mount
        };
    }
    ```
    - The code iterates through the `mount` configuration from `Config.getMount`.
    - For each `mountRule`, it resolves the second element (file path) using `path.resolve(workspacePath, mountRule[1])`.
    - **Vulnerability:**  It directly uses `mountRule[0]` (URL path) without any validation or sanitization when passing it to the `live-server` library. This allows users to specify arbitrary URL paths, including those with path traversal sequences.

* Security Test Case:
    1. Open VSCode with any workspace.
    2. Create a file named `test.txt` in the workspace root with content "This is a test file".
    3. Open VSCode settings (JSON) and add the following configuration:
       ```json
       "liveServer.settings.mount": [
           ["/../../../../", "/"]
       ]
       ```
    4. Start Live Server using any method (e.g., "Go Live" button in the status bar).
    5. Determine the port Live Server is running on (e.g., check the information message or status bar). Let's say the port is `<port>`.
    6. Open a web browser and navigate to the URL: `http://localhost:<port>/../../../../<absolute_path_to_workspace>/test.txt`. Replace `<absolute_path_to_workspace>` with the actual absolute path to your workspace directory (e.g., `/home/user/myproject` on Linux or `C:/Users/User/Documents/myproject` on Windows).
    7. Observe the browser's response.
    8. **Expected Result (Vulnerable):** If the content of `test.txt` ("This is a test file") is displayed in the browser, it confirms the path traversal vulnerability. This means you have successfully accessed a file within your workspace using path traversal.
    9. **Further Test (Critical Vulnerability):** To test for more critical path traversal, try accessing system files. For example, on Linux, navigate to `http://localhost:<port>/../../../../etc/passwd`. On Windows, try `http://localhost:<port>/../../../../Windows/win.ini`.
    10. **Expected Result (Critically Vulnerable):** If you can access system files like `/etc/passwd` or `win.ini`, it confirms a critical path traversal vulnerability, allowing access to sensitive system information.