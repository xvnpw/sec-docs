### Vulnerability List

- Vulnerability Name: Workspace Mount Path Traversal
- Description:
    1. Attacker configures the `liveServer.settings.mount` setting in VSCode settings.json.
    2. Attacker sets the mount path to a directory outside the workspace using relative path like `["/mounted", "../../../"]`.
    3. Attacker starts the Live Server.
    4. Attacker accesses the mounted path using the configured route, e.g., `http://localhost:port/mounted/sensitive_file.txt`.
    5. The server serves files from outside the workspace due to path traversal in mount path.
- Impact:
    - High: Attacker can access sensitive files outside the workspace if the user configures a vulnerable mount path. This could lead to information disclosure of sensitive data located on the user's file system.
- Vulnerability Rank: high
- Currently implemented mitigations:
    - None: The application resolves the mount path relative to the workspace, but it does not prevent using relative paths like `../` to traverse outside the workspace.
- Missing mitigations:
    - Sanitize and validate the mount path in `liveServer.settings.mount` to prevent path traversal. Ensure that the resolved mount path is within the workspace directory or restrict the usage of relative paths in mount configuration. A secure approach would be to resolve the mount path relative to the workspace and then verify that the resolved path is still within the workspace directory using path comparison methods.
- Preconditions:
    - User must have VSCode with Live Server extension installed.
    - Attacker needs to convince the user to add a malicious configuration to their VSCode settings.json, or have access to modify the user's VSCode settings.json directly.
- Source code analysis:
    - In `src/Helper.ts`, the `generateParams` function processes the `liveServer.settings.mount` configuration:
    ```typescript
    mount.forEach((mountRule: Array<any>) => {
        if (mountRule.length === 2 && mountRule[1]) {
            mountRule[1] = path.resolve(workspacePath, mountRule[1]); // Resolves mount path relative to workspacePath
        }
    });
    ```
    - `path.resolve(workspacePath, mountRule[1])` resolves the mount path relative to the workspace path. This allows relative paths like `../` within `mountRule[1]` to traverse directories outside of the intended workspace.
    - In `lib/live-server/index.js`, this resolved `mountPath` is then used to serve static files:
    ```javascript
    app.use(mountRule[0], staticServer(mountPath, staticServer, onTagMissedCallback));
    ```
    - Because the mount path resolution doesn't restrict paths to stay within the workspace, it leads to a path traversal vulnerability.
- Security test case:
    1. Open VSCode with any workspace directory.
    2. Create a sensitive file named `sensitive.txt` outside the workspace directory, for example in your user's home directory. Add content like "This is sensitive data." to the file.
    3. Open VSCode settings (settings.json) for the workspace.
    4. Add the following configuration to `settings.json`:
       ```json
       {
           "liveServer.settings.mount": [
               ["/mounted", "../../../../"]
           ]
       }
       ```
       Adjust the number of `../` to correctly point to the directory containing `sensitive.txt` from your workspace location. For instance, if your workspace is in `/home/user/project` and `sensitive.txt` is in `/home/user/`, use `["/mounted", "../../"]`.
    5. Create or open any HTML file (e.g., `index.html`) within your workspace.
    6. Start Live Server by clicking "Go Live" from the status bar or using the command palette.
    7. Open a web browser and navigate to `http://localhost:5500/mounted/sensitive.txt`. If port `5500` is in use, use the actual port Live Server is running on.
    8. Observe that the content of `sensitive.txt`, "This is sensitive data.", is displayed in the browser. This confirms that you have successfully accessed a file outside the workspace through the mounted path, demonstrating the path traversal vulnerability.