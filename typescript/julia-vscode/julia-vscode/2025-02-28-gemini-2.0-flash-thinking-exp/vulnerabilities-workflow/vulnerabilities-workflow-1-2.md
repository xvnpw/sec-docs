## Vulnerability List for Julia VSCode Extension

### 1. Path Traversal in Julia Executable Path Configuration

- Description:
    1. A malicious user can configure the `julia.executablePath` setting in VSCode to point to a location outside of the intended Julia installation directory.
    2. The `resolvePath` function in `/code/src/utils.ts` normalizes the provided path, but it does not prevent path traversal sequences like `..` from being resolved.
    3. When the Julia VS Code extension starts or restarts the Language Server or REPL, it uses the configured `julia.executablePath` to spawn a Julia process.
    4. By setting `julia.executablePath` to a path containing path traversal sequences (e.g., `/../../../../bin/sh` or `C:\..\..\..\..\windows\system32\cmd.exe`), an attacker can force the extension to execute arbitrary executables on the user's system instead of the intended Julia binary.
    5. This can be achieved even if the attacker only has control over user settings, for instance, by tricking a user into opening a workspace with a malicious `.vscode/settings.json` file.

- Impact:
    - **High:** Arbitrary code execution. An attacker can gain arbitrary code execution on the user's machine with the privileges of the VSCode process by setting a malicious executable path. This could lead to complete compromise of the user's system, including data theft, malware installation, or further attacks.

- Vulnerability Rank: high

- Currently implemented mitigations:
    - None in the code related to path traversal prevention for `julia.executablePath`. The `filterTelemetry` function in `/code/src/telemetry.ts` filters stack traces, but this is unrelated to this vulnerability.

- Missing mitigations:
    - Input validation for `julia.executablePath` to prevent path traversal sequences.
    - Check if the resolved path is within an expected or safe directory.
    - Avoid executing user-provided paths directly if possible, or use safer APIs for process execution that prevent command injection and path traversal.

- Preconditions:
    - User must install the Julia VS Code extension.
    - Attacker needs to be able to influence the `julia.executablePath` setting, e.g., by providing a malicious workspace configuration file or by social engineering to get the user to manually change the setting.

- Source code analysis:
    1. **File: `/code/src/utils.ts`**
    ```typescript
    export function resolvePath(p: string, normalize: boolean = true) {
        p = parseVSCodeVariables(p) // User-controlled variables are parsed
        p = p.replace(/^~/, os.homedir())
        p = normalize ? path.normalize(p) : p // path.normalize() resolves '..' sequences
        return p
    }
    ```
    The `resolvePath` function normalizes the path, but doesn't prevent traversal.
    2. **File: `/code/src/juliaexepath.ts`**
    ```typescript
    async function startLanguageServer(juliaExecutablesFeature: JuliaExecutablesFeature) {
        // ...
        const serverOptions: ServerOptions = Boolean(process.env.DETACHED_LS) ?
            async () => {
                // ...
            } :
            {
                run: { command: juliaLSExecutable.file, args: [...juliaLSExecutable.args, ...serverArgsRun], options: spawnOptions }, // Julia executable is spawned here
                debug: { command: juliaLSExecutable.file, args: [...juliaLSExecutable.args, ...serverArgsDebug], options: spawnOptions } // And here
            }
        // ...
    ```
    The `juliaLSExecutable.file`, which is derived from `julia.executablePath` setting, is directly used in `spawn` without further validation.
    3. **File: `/code/src/juliaexepath.ts`**
    ```typescript
    async tryAndSetNewJuliaExePathAsync(newPath: string) {
        const newJuliaExecutable = await this.tryJuliaExePathAsync(newPath) // Calls tryJuliaExePathAsync with user-controlled path

        if (newJuliaExecutable) {
            this.actualJuliaExePath = newJuliaExecutable
            setCurrentJuliaVersion(this.actualJuliaExePath.version)
            traceEvent('configured-new-julia-binary')

            return true
        } else {
            return false
        }
    }

    async tryJuliaExePathAsync(newPath: string) {
        try {
            let parsedPath = ''
            let parsedArgs = []

            if (path.isAbsolute(newPath) && await exists(newPath)) {
                parsedPath = newPath
            } else {
                const resolvedPath = resolvePath(newPath, false) // resolvePath is called here
                if (path.isAbsolute(resolvedPath) && await exists(resolvedPath)) {
                    parsedPath = resolvedPath
                } else {
                    const argv = stringArgv(newPath)

                    parsedPath = argv[0]
                    parsedArgs = argv.slice(1)
                }
            }
            const { stdout, } = await execFile(  // execFile is called with the potentially malicious path
                parsedPath,
                [...parsedArgs, '--version'],
                {
                    env: {
                        ...process.env,
                        JULIA_VSCODE_INTERNAL: '1',
                    }
                }
            )
        // ...
    ```
    `tryJuliaExePathAsync` uses `resolvePath` and then `execFile` with the resolved path.

- Security test case:
    1. Create a new VSCode workspace.
    2. Create a `.vscode` folder in the workspace root.
    3. Inside `.vscode` folder, create a `settings.json` file with the following content to set a malicious executable path (adjust path based on your OS):
    ```json
    {
        "julia.executablePath": "/bin/sh"  // For Linux/macOS, or "C:\\windows\\system32\\cmd.exe" for Windows
    }
    ```
    or for path traversal:
    ```json
    {
        "julia.executablePath": "/../../../../bin/sh"  // For Linux/macOS, or "C:\\..\\..\\..\\..\\windows\\system32\\cmd.exe" for Windows
    }
    ```
    4. Open VSCode in this workspace.
    5. Observe if the Julia VSCode extension activates without errors (it might show errors if `/bin/sh` or `cmd.exe` is not a valid Julia executable, but the vulnerability is still triggerable).
    6. Try to execute any Julia command in VSCode (e.g., open a Julia file and try to run it).
    7. Instead of Julia code execution, the system shell or `cmd.exe` will be executed, demonstrating arbitrary code execution.
    8. For a more concrete test, replace `/bin/sh` in `settings.json` with `/bin/sh -c "touch /tmp/pwned.txt"` (Linux/macOS) or `C:\\windows\\system32\\cmd.exe /c echo pwned > %TEMP%\\pwned.txt` (Windows).
    9. After VSCode activates and tries to start Julia (or when you trigger any Julia command), check if the file `/tmp/pwned.txt` (Linux/macOS) or `%TEMP%\\pwned.txt` (Windows) is created. If yes, arbitrary code execution is confirmed.