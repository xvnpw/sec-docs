- vulnerability name: Unvalidated .NET runtime path from settings
  description: |
    The C# extension allows users to specify a custom .NET runtime path via the `omnisharp.dotnetPath` setting. If an attacker can convince a user to set this path to a malicious executable, the extension could execute arbitrary code from that path when starting the OmniSharp server. This scenario is less likely because it requires user interaction to change settings but still possible.
    1. Attacker crafts a malicious executable and hosts it at a publicly accessible location or convinces user to place it locally.
    2. Attacker social engineers a victim into setting the `omnisharp.dotnetPath` setting in VSCode to point to the malicious executable.
    3. When the C# extension activates or restarts OmniSharp, it executes the specified path.
  impact: Arbitrary code execution on the user's machine with the privileges of the VSCode process.
  vulnerability rank: high
  currently implemented mitigations:
    - The extension recommends using the .NET Install Tool to manage .NET runtimes, which reduces the likelihood of users manually setting arbitrary paths.
  missing mitigations:
    - Input validation: The extension should validate that the path specified in `omnisharp.dotnetPath` actually points to a valid .NET runtime executable before attempting to launch it. This could include checks for file type, existence of required libraries, and digital signature verification.
    - Sandboxing: Running the OmniSharp server in a sandboxed environment could limit the impact of arbitrary code execution, although this may be complex to implement for a VSCode extension.
  preconditions:
    - User must manually configure the `omnisharp.dotnetPath` setting to an attacker-controlled executable.
  source code analysis: |
    1. In `src/omnisharp/dotnetResolver.ts`, the `getHostExecutableInfo` function retrieves the dotnet path from `omnisharpOptions.dotnetPath`.
    ```typescript
    const dotnetPathOption = omnisharpOptions.dotnetPath;
    if (dotnetPathOption.length > 0) {
        env['PATH'] = dotnetPathOption + path.delimiter + env['PATH'];
    }
    ```
    2. This path is then used to execute the dotnet command:
    ```typescript
    const command = dotnetExecutablePath ? `"${dotnetExecutablePath}"` : 'dotnet';
    const data = await execChildProcess(`${command} --info`, process.cwd(), env);
    ```
    Based on the code analysis of `src/omnisharp/launcher.ts`, `src/omnisharp/server.ts` and `src/omnisharp/engines/stdioEngine.ts`, the `launchOmniSharp` function in `launcher.ts` and the `StdioEngine.start` in `stdioEngine.ts` utilize `dotnetResolver.getHostExecutableInfo()` to determine the dotnet executable path. The `getHostExecutableInfo` in `dotnetResolver.ts` directly uses the `omnisharpOptions.dotnetPath` setting without validation. This confirms that a malicious path provided via `omnisharp.dotnetPath` will be used to launch the OmniSharp server, leading to arbitrary code execution if a malicious executable is placed at that path.
  security test case:
    1. Create a malicious executable (e.g., `malicious.exe` on Windows, `malicious` on Linux/macOS) that, when run, executes some harmful command (e.g., creates a file in the user's home directory, or attempts to access sensitive data - for testing purposes only, avoid actual harm).
    2. Place this malicious executable at a known location on your system.
    3. In VSCode, open the settings (Ctrl+,) and search for `omnisharp.dotnetPath`.
    4. Set the `omnisharp.dotnetPath` setting to the path of your malicious executable.
    5. Reload VSCode (`Ctrl+Shift+P`, type "Reload Window", and press Enter).
    6. Observe if the malicious executable is executed when the C# extension starts. You can verify this by checking for the side effects of the malicious executable (e.g., the creation of the test file).
    7. Reset the `omnisharp.dotnetPath` setting to its default value or a valid .NET SDK path after testing.