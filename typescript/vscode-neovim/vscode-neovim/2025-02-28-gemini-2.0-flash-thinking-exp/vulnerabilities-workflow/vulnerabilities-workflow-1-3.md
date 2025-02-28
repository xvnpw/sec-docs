- Vulnerability name: Code injection through `vscode.eval` and `vscode.eval_async` Lua API
- Description:
    - An attacker can control the `code` argument of the `vscode.eval` or `vscode.eval_async` Lua API calls.
    - By crafting malicious Javascript code and passing it as the `code` argument, an attacker can execute arbitrary Javascript code within the VSCode extension's context.
    - This can be achieved by calling `vscode.eval` or `vscode.eval_async` with a crafted `code` argument from Neovim using `nvim_command` or similar methods.
    - The executed Javascript code has access to the full VSCode API via the `vscode` global variable, allowing the attacker to perform actions such as:
        - Reading and writing files on the user's system.
        - Executing arbitrary VSCode commands.
        - Exfiltrating sensitive information.
        - Modifying extension settings.
        - Interacting with other VSCode extensions if APIs are exposed.
- Impact:
    - Critical: Remote Code Execution (RCE) within the VSCode extension host.
    - An attacker can gain full control over the VSCode environment and potentially the user's system, depending on the permissions of the VSCode process.
- Vulnerability rank: critical
- Currently implemented mitigations:
    - None in the provided code. The API is exposed without any input sanitization or access control.
- Missing mitigations:
    - Input sanitization and validation for the `code` argument in `vscode.eval` and `vscode.eval_async`.
    - Principle of least privilege: Restrict the capabilities of the Javascript code executed via `vscode.eval` and `vscode.eval_async` to the bare minimum required. However, given the nature of the API, complete mitigation without breaking functionality might be challenging.
    - Documentation explicitly warning against executing untrusted Javascript code via this API. However, documentation alone is not a mitigation against direct exploitation.
- Preconditions:
    - The attacker needs to be able to execute commands within Neovim, which is the standard threat model for VSCode extensions integrating with external editors.
    - The extension must be running and the Neovim instance connected to the extension must be under the attacker's control or influence (e.g., through a malicious Neovim configuration).
- Source code analysis:
    - File: `/code/src/actions_eval.ts`
    ```typescript
    export async function eval_for_client(code: string, args: any): Promise<any> {
        void args;

        const func: () => Promise<any> = eval("async () => {" + code + "}"); // Vulnerability: Using eval to execute code argument

        const result = await func();

        let data: string | undefined;
        try {
            data = JSON.stringify(result);
        } catch (e) {
            throw new Error(`Return value of eval not JSON serializable: ${e}`);
        }

        return data ? JSON.parse(data) : data;
    }
    ```
    - The `eval_for_client` function directly uses the `eval()` function in Javascript to execute the `code` argument, which is a string passed from Lua.
    - There is no sanitization or validation of the `code` argument before it is passed to `eval()`.
    - File: `/code/src/actions.ts`
    ```typescript
        this.add("eval", (code: string, args: any) => eval_for_client(code, args));
        this.add("eval_async", (code: string, args: any, callback: string) => { //Note: eval_async is not in the API doc, but it exists in code
            eval_for_client(code, args).then(
                (result) => {
                    if (callback) {
                        this.client?.executeLua('require"vscode.api".invoke_callback(...)', [
                            callback,
                            result,
                            false,
                        ]);
                    }
                },
                (err: Error) => {
                    if (callback) {
                        this.client?.executeLua('require"vscode.api".invoke_callback(...)', [callback, err.message, true]);
                    }
                },
            );
        });
    ```
    - The `actions.ts` file registers the `eval` and `eval_async` actions, which are callable from Neovim.
    - These actions directly pass the `code` argument to the vulnerable `eval_for_client` function.

- Security test case:
    - Precondition: VSCode with vscode-neovim extension installed and connected to a Neovim instance.
    - Step 1: Open VSCode with the vscode-neovim extension active.
    - Step 2: Open any text file in VSCode.
    - Step 3: In Neovim, execute the following command:
    ```vimscript
    :lua require('vscode').eval('require("child_process").exec("touch /tmp/pwned")', {})
    ```
    - Step 4: Check if the file `/tmp/pwned` has been created on the system.
    - Step 5: If the file `/tmp/pwned` exists, the vulnerability is confirmed.
    - Step 6: Alternatively, try a more benign but visible command like showing an information message:
    ```vimscript
    :lua require('vscode').eval('vscode.window.showInformationMessage("PWNED!")', {})
    ```
    - Step 7: Check if a VSCode information message "PWNED!" is displayed.
    - Step 8: If the message is displayed, the vulnerability is confirmed.

This vulnerability allows for critical impact, as it enables arbitrary code execution within the VSCode extension host, making it a critical vulnerability.