### Vulnerability List for VSCode Neovim Extension

- Vulnerability Name: **Lua Code Injection via `vscode.eval` and `vscode.eval_async` API**
- Description:
    1. An attacker can control Neovim configuration through `init.lua` or `init.vim`.
    2. The attacker configures Neovim to execute arbitrary Javascript code within the VSCode extension context using the `vscode.eval` or `vscode.eval_async` Lua API functions.
    3. Since the Javascript code is executed within the extension's context, it has full access to the VSCode API and Node.js environment, potentially allowing for malicious actions.
- Impact:
    - **Critical**: Remote Code Execution (RCE). An attacker can execute arbitrary code on the user's machine with the privileges of the VSCode extension host process. This could lead to data theft, installation of malware, or complete system compromise.
- Vulnerability Rank: critical
- Currently implemented mitigations:
    - None. The API is intended for legitimate extension functionality.
- Missing mitigations:
    - **Input validation and sanitization**: While challenging due to the nature of code evaluation, some form of sandboxing or permission control for `vscode.eval` and `vscode.eval_async` could limit the impact of arbitrary code execution. However, this is likely to severely restrict the intended functionality of the API.
    - **Principle of least privilege**: Consider if such powerful API access is absolutely necessary for the core functionality of the extension. If not, restricting or removing these APIs would be the most effective mitigation.
- Preconditions:
    - The user must have the VSCode Neovim extension installed.
    - The attacker must be able to modify the user's Neovim configuration files (e.g., `init.lua` or `init.vim`). This could be achieved through social engineering, phishing, or exploiting other vulnerabilities to gain access to the user's file system.
- Source code analysis:
    1. **API Exposure**: The `vscode.eval` and `vscode.eval_async` functions are exposed to Neovim Lua scripts through the `vscode` module (see `/code/README.md` and `/code/runtime/lua/vscode.lua`).
    2. **Code Execution**: These functions, implemented in `/code/src/actions_eval.ts`, use `eval()` in Javascript to execute arbitrary code strings provided from Lua.
    ```typescript
    // File: /code/src/actions_eval.ts
    export async function eval_for_client(code: string, args: any): Promise<any> {
        void args;

        const func: () => Promise<any> = eval("async () => {" + code + "}"); // Vulnerable code: Using eval() to execute arbitrary code
        const result = await func();
    ```
    3. **Full Access to VSCode API**: Code executed via `eval()` has access to the `vscode` global, which provides the entire VSCode API. This allows the attacker to perform any action that the VSCode extension is capable of.

- Security test case:
    1. **Prerequisites**:
        - Install the VSCode Neovim extension.
        - Ensure Neovim is installed and configured for use with the extension.
        - Have a publicly accessible instance of a VSCode project where you can modify Neovim configuration files.
    2. **Modify Neovim Configuration**:
        - Open your `init.lua` or `init.vim` file. If you don't have one, create it in your Neovim configuration directory (e.g., `~/.config/nvim/init.lua` or `~/.vimrc`).
        - Add the following Lua code to `init.lua` (or equivalent VimScript to `init.vim`):
        ```lua
        vim.api.nvim_command [[
          nnoremap <leader>x :lua require('vscode').eval("vscode.window.showErrorMessage('Vulnerability Triggered!')")<CR>
        ]]
        ```
        or in `init.vim`:
        ```vimscript
        nnoremap <leader>x :lua require('vscode').eval("vscode.window.showErrorMessage('Vulnerability Triggered!')")<CR>
        ```
        This mapping will execute Javascript code to display an error message when `<leader>x` is pressed in normal mode.
    3. **Trigger Vulnerability**:
        - Open any text file in VSCode.
        - Enter normal mode (if not already in normal mode).
        - Press `<leader>x` (by default, `<leader>` is `\`, so press `\x`).
    4. **Verify Impact**:
        - An error message box with the text "Vulnerability Triggered!" should appear in VSCode, confirming that arbitrary Javascript code was executed within the extension context.
        - **Further Exploitation (Optional but recommended for full verification):**
            - Replace the payload in `init.lua` with code that performs a more impactful action, such as:
            ```lua
            vim.api.nvim_command [[
              nnoremap <leader>x :lua require('vscode').eval("vscode.env.clipboard.writeText('Exploited!')")<CR>
            ]]
            ```
            - After pressing `<leader>x`, try pasting (e.g., `Ctrl+V` or `Cmd+V`) in another application. The clipboard should contain "Exploited!", demonstrating the ability to interact with system functionalities via RCE.