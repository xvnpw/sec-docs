## Consolidated Vulnerability Report

This report consolidates identified vulnerabilities from multiple lists into a single, de-duplicated list, providing detailed descriptions, impacts, mitigations, and steps for verification.

### 1. Command Injection in `askpass.sh` via Unsanitized Arguments (Merged Vulnerability)

- **Vulnerability Name:** Command Injection in `askpass.sh` via Unsanitized Arguments

- **Description:**
    1. The Git Graph extension utilizes `askpass.sh` (and `askpass-empty.sh`) as Git credential helpers for authentication with remote repositories.
    2. The `askpass.sh` script is designed to handle password prompts for Git operations. It receives arguments from Git commands and passes them directly to a Node.js script (`VSCODE_GIT_GRAPH_ASKPASS_NODE`, `VSCODE_GIT_GRAPH_ASKPASS_MAIN`) using `$*` without any sanitization.
    3. The Node.js script (`askpassMain.ts` or `askpassMain.js`) receives these arguments through `process.argv`. It extracts the 2nd argument (`argv[2]`) as `request` and a portion of the 4th argument (`argv[4]`) as `host`.
    4. These extracted `request` and `host` values are then used to construct a prompt message in a VSCode input box via the `AskpassManager::onRequest` function in the extension's backend. The Node.js script sends these values as a JSON payload via HTTP POST to the extension's backend.
    5.  `AskpassManager::onRequest` receives this HTTP request, parses the JSON payload, and directly uses the `request` value as `placeHolder` and `host` value (prefixed with "Git Graph: ") as `prompt` options in `vscode.window.showInputBox`.
    6. While `vscode.window.showInputBox` itself is not directly vulnerable to command injection, the unsanitized nature of how arguments are passed from Git commands through `askpass.sh` and `askpassMain.ts`/`askpassMain.js` to the extension backend introduces a critical security risk.
    7. If Git commands constructed by the extension incorporate user-controlled or externally influenced strings into arguments that eventually reach `askpass.sh`, an attacker can inject malicious commands. By crafting specific Git commands (e.g., during clone, fetch, or push operations) that trigger `askpass.sh` and include malicious payloads within arguments (like username or remote URL), an attacker can potentially achieve arbitrary command execution.
    8. The vulnerability is not directly in `showInputBox` but arises from the initial unsanitized passing of arguments in `askpass.sh` and the potential for the extension or Git to unsafely utilize user-provided credentials from `showInputBox` in subsequent Git commands. This could lead to command injection if the response from `showInputBox` is later incorporated into shell commands without proper sanitization.

- **Impact:**
    - Successful command injection can allow an attacker to execute arbitrary commands on the machine where the VSCode extension is running.
    - This could lead to severe consequences, including:
        - Data theft and unauthorized access to sensitive information.
        - System compromise, allowing the attacker to gain control over the user's machine.
        - Installation of malware, including persistent backdoors for future access.
        - Further propagation of attacks within the network, potentially compromising other systems.

- **Vulnerability Rank:** Critical

- **Currently Implemented Mitigations:**
    - Based on the analyzed files (`askpass.sh`, `askpassMain.ts`, `askpassManager.ts`, `/code/web/settingsWidget.ts`), there are no explicit mitigations implemented to address this command injection vulnerability.
    - The `askpass.sh` script directly passes arguments without sanitization.
    - The Node.js scripts and backend code do not sanitize the arguments before using them in `vscode.window.showInputBox` or further processing.

- **Missing Mitigations:**
    - **Input sanitization in `askpass.sh`**:  Crucially, `askpass.sh` must sanitize all arguments (`$*`) before passing them to the Node.js script. This should involve robust validation and escaping of shell arguments to prevent any interpretation as shell commands.
    - **Input sanitization in Node.js askpass script (`askpassMain.ts`/`askpassMain.js`)**: Although `askpassMain.ts`/`askpassMain.js` itself does not execute shell commands, sanitizing the received arguments before forwarding them via HTTP would provide defense in depth.
    - **Input sanitization in `AskpassManager::onRequest`**: Sanitize the `request` and `host` values received in `AskpassManager::onRequest` before using them as `placeHolder` and `prompt` in `vscode.window.showInputBox`. While not the primary injection point, this adds another layer of security.
    - **Secure Git command construction in the extension**:  Thoroughly review the extension's codebase where Git commands are constructed and executed. Ensure that user-controlled input or external data is never directly incorporated into Git command arguments without strict sanitization or parameterization.
    - **Sanitization of user credentials**: Review how the user-provided credentials obtained from `vscode.window.showInputBox` are used in subsequent Git commands. Implement robust sanitization to prevent command injection vulnerabilities arising from unsafely using these credentials in shell commands.
    - **Consider safer alternatives to shell script for handling password prompts**: Explore if password prompts can be managed directly within Node.js or using safer APIs that avoid shell command injection risks altogether.

- **Preconditions:**
    - The Git Graph extension must be installed and active in VSCode.
    - The attacker needs to trigger a Git operation that necessitates the use of `askpass.sh` for authentication (e.g., accessing a private repository over HTTPS or SSH requiring password authentication).
    - The attacker must be able to influence the arguments passed to the `askpass.sh` script through a malicious Git repository or crafted Git command. This influence point resides within the Git command construction logic within the extension's source code.
    - The extension must be vulnerable to command injection through the user-provided credentials obtained via `vscode.window.showInputBox`.

- **Source Code Analysis:**
    - **File:** `/code/src/askpass/askpass.sh`
        ```sh
        #!/bin/sh
        VSCODE_GIT_GRAPH_ASKPASS_PIPE=`mktemp`
        VSCODE_GIT_GRAPH_ASKPASS_PIPE="$VSCODE_GIT_GRAPH_ASKPASS_PIPE" "$VSCODE_GIT_GRAPH_ASKPASS_NODE" "$VSCODE_GIT_GRAPH_ASKPASS_MAIN" $*
        cat $VSCODE_GIT_GRAPH_ASKPASS_PIPE
        rm $VSCODE_GIT_GRAPH_ASKPASS_PIPE
        ```
        - **Vulnerable Step:** The line `VSCODE_GIT_GRAPH_ASKPASS_PIPE="$VSCODE_GIT_GRAPH_ASKPASS_PIPE" "$VSCODE_GIT_GRAPH_ASKPASS_NODE" "$VSCODE_GIT_GRAPH_ASKPASS_MAIN" $*` is critically vulnerable. `$*` expands to all arguments passed to `askpass.sh` and is directly appended to the command executed without any form of sanitization or escaping. This allows for immediate command injection if malicious arguments are provided.

    - **File:** `/code/src/askpass/askpassMain.ts` (or `askpassMain.js`)
        ```typescript
        // ... imports ...
        function main(argv: string[]): void {
            if (argv.length !== 5) return fatal('Wrong number of arguments');
            if (!process.env['VSCODE_GIT_GRAPH_ASKPASS_HANDLE']) return fatal('Missing handle');
            if (!process.env['VSCODE_GIT_GRAPH_ASKPASS_PIPE']) return fatal('Missing pipe');

            const output = process.env['VSCODE_GIT_GRAPH_ASKPASS_PIPE']!;
            const socketPath = process.env['VSCODE_GIT_GRAPH_ASKPASS_HANDLE']!;

            const req = http.request({ socketPath, path: '/', method: 'POST' }, res => { /* ... */ });

            req.on('error', () => fatal('Error in request'));
            req.write(JSON.stringify({ request: argv[2], host: argv[4].substring(1, argv[4].length - 2) }));
            req.end();
        }
        main(process.argv);
        ```
        - **Argument Handling:** `askpassMain.ts`/`askpassMain.js` extracts and uses `argv[2]` and `argv[4]` from the unsanitized arguments passed by `askpass.sh`. These are then incorporated into a JSON payload and sent to the extension backend. No sanitization is performed on these arguments in this script.

    - **File:** `/code/src/askpass/askpassManager.ts`
        ```typescript
        // ... imports ...
        export class AskpassManager extends Disposable {
            // ...
            private onRequest(req: http.IncomingMessage, res: http.ServerResponse): void {
                let reqData = '';
                req.setEncoding('utf8');
                req.on('data', (d) => reqData += d);
                req.on('end', () => {
                    let data = JSON.parse(reqData) as AskpassRequest;
                    vscode.window.showInputBox({ placeHolder: data.request, prompt: 'Git Graph: ' + data.host, password: /password/i.test(data.request), ignoreFocusOut: true }).then(result => { // ... });
                });
            }
            // ...
        }
        ```
        - **Unsanitized Usage in `showInputBox`:** The `AskpassManager::onRequest` function directly uses `data.request` and `data.host` (received unsanitized from `askpassMain.ts`/`askpassMain.js`) as `placeHolder` and `prompt` in `vscode.window.showInputBox`. This presents the attacker-controlled strings directly to the user interface, and while not the direct injection point, it highlights the flow of unsanitized data.

    - **Visualization:**

    ```
    [Git Command with Askpass] --> askpass.sh (arguments: $* from Git command)
                                        |  (VULNERABILITY: Unsanitized $* passed to next command)
                                        V
    askpass.sh executes:  [Node.js executable] [Node.js askpass script] $*
                                        |
                                        V
    [Node.js askpass script processes arguments ($*) and sends via HTTP to backend]
                                        |
                                        V
    AskpassManager::onRequest (receives unsanitized arguments)
                                        |
                                        V
    vscode.window.showInputBox (uses unsanitized arguments in prompt)
                                        |
                                        V
    [User provides credentials]
                                        |
                                        V
    [Credentials potentially used in subsequent Git commands - POTENTIAL INJECTION POINT]
    ```

- **Security Test Case:**
    1. **Precondition:** Set up a private Git repository that requires password authentication over HTTPS. Ensure the Git Graph extension is active.
    2. **Craft Malicious Git Command (via remote name):** Construct a Git command that triggers `askpass.sh` and injects a command. Use a specially crafted remote name during a `git fetch` operation:
        ```bash
        git fetch origin "evil'$(touch /tmp/pwned_askpass_injection)'"
        ```
    3. **Execute Git Command in VSCode via Git Graph:** Use the Git Graph extension to trigger a "Fetch from Remote(s)..." operation for the configured repository. This should initiate the Git fetch command.
    4. **Provide Dummy Credentials:** When prompted for credentials by the VSCode input box (triggered by `askpass.sh`), enter any dummy password and username.
    5. **Observe System for Command Execution:** After providing credentials and proceeding, check if the file `/tmp/pwned_askpass_injection` has been created.
    6. **Verify Vulnerability:** If `/tmp/pwned_askpass_injection` exists, it confirms successful command injection via arguments passed to `askpass.sh`. The injection occurs when the malicious remote name is processed, leading to the execution of `touch /tmp/pwned_askpass_injection`.


### 2. DOM–based Cross–Site Scripting (XSS) in the Find Widget

- **Vulnerability Name:** DOM–based Cross–Site Scripting (XSS) in the Find Widget

- **Description:**
    1. The Find Widget in the Git Graph View ("web/findWidget.ts") is responsible for highlighting search matches within the commit graph.
    2. To highlight matches, the widget uses the helper method `createMatchElem()`. This method takes substrings of text nodes (extracted from commit data) and inserts them into new `<span>` elements.
    3. Critically, `createMatchElem()` sets the `innerHTML` of these `<span>` elements directly with the substrings, without any output sanitization.
    4. If an attacker can inject a malicious payload (e.g., `<img src=x onerror=alert(1)>`) into Git commit data (commit messages, branch names, tags), this payload will be executed when the Find Widget processes and highlights the matching text.
    5. When a user searches for a term that matches part of the malicious payload in the commit data, the unsanitized substring containing the payload is passed to `createMatchElem()`.
    6. As `innerHTML` is used, the browser interprets and executes the injected HTML/JavaScript payload, resulting in DOM-based XSS.

- **Impact:**
    - Arbitrary script execution within the context of the extension window.
    - Attackers can potentially access internal VS Code APIs and data.
    - Modification of extension behavior or complete compromise of the extension.
    - Potential compromise of the host editor's environment.

- **Vulnerability Rank:** High

- **Currently Implemented Mitigations:**
    - No mitigations are implemented in the `createMatchElem()` method or the Find Widget code to prevent XSS.
    - Substrings from commit data are directly assigned to `innerHTML` without sanitization.
    - No output encoding or safe DOM insertion methods are used.

- **Missing Mitigations:**
    - **Output Sanitization:** Apply proper output encoding/sanitization to any user-controlled text (especially from commit data) before inserting it into the DOM.
    - **Use `textContent`:** Replace `innerHTML` with `textContent` for inserting text content to prevent HTML interpretation. If HTML is required, use a secure HTML templating system with automatic escaping or DOMPurify to sanitize HTML.
    - **Avoid `innerHTML`:** Avoid using `innerHTML` for content derived from potentially untrusted sources like commit data.

- **Preconditions:**
    - The attacker must be able to control a portion of Git commit data (commit messages, branch/tag names). This could be achieved by creating or contributing to a malicious repository.
    - A victim user must load this malicious repository in Git Graph.
    - The victim must use the Find Widget and enter a search term that matches part of the malicious payload in the commit data.

- **Source Code Analysis:**
    - **File:** `web/findWidget.ts`
        ```typescript
        private static createMatchElem(text: string) {
            const span = document.createElement('span');
            span.className = CLASS_FIND_MATCH;
            span.innerHTML = text; // Vulnerable line: unsanitized text to innerHTML
            return span;
        }
        ```
    - **Vulnerable Step:** The line `span.innerHTML = text;` directly assigns the `text` (substring from commit data) to the `innerHTML` of the `span` element. This is the source of the DOM-based XSS vulnerability.
    - The `findMatches()` method and other Find Widget logic extract substrings from commit data and pass them to `createMatchElem()`.

- **Security Test Case:**
    1. **Create Malicious Repository:** Create or contribute to a Git repository with a commit message containing the payload: `<img src=x onerror=alert(1)>`.
    2. **Open Repository in Git Graph:** Open the malicious repository in VS Code with the Git Graph extension.
    3. **Open Find Widget and Search:** Open the Find Widget and enter a search term that matches part of the malicious payload (e.g., "img").
    4. **Verify XSS:** Observe if an alert box appears when the Find Widget highlights the matching text. The alert confirms the execution of the injected JavaScript payload and thus the DOM-based XSS vulnerability.

### 3. Stored DOM–Based Cross–Site Scripting (XSS) via Custom Emoji Mappings in TextFormatter

- **Vulnerability Name:** Stored DOM–Based Cross–Site Scripting (XSS) via Custom Emoji Mappings in TextFormatter

- **Description:**
    1. The TextFormatter ("web/textFormatter.ts") in the extension handles text formatting, including parsing for commit hashes, URLs, markdown, and custom emojis.
    2. The `TextFormatter.registerCustomEmojiMappings()` method allows registering custom emoji mappings. These mappings consist of a shortcode (e.g., `:emoji:`) and an associated emoji string.
    3. While shortcodes are validated to match the format `/^:[A-Za-z0-9-_]+:$/`, the emoji values themselves are **not sanitized**.
    4. When formatting text, the TextFormatter checks for emoji shortcodes and, if a match is found in `TextFormatter.EMOJI_MAPPINGS`, creates an Emoji node containing the stored emoji value.
    5. During HTML generation in `formatLine()`, the emoji value from the Emoji node is directly inserted into the HTML output using `html.push(node.emoji);` without any output encoding.
    6. This lack of sanitization on the emoji value allows an attacker to inject malicious HTML/JavaScript code (e.g., `<img src=x onerror=alert("XSS")>`) as a custom emoji mapping.
    7. When text containing the corresponding shortcode is processed by the TextFormatter, the malicious payload is rendered directly into the DOM, leading to stored DOM-based XSS.

- **Impact:**
    - Arbitrary script execution in the extension's context.
    - Potential compromise of sensitive data and manipulation of the Git Graph interface.
    - Abuse of internal VS Code APIs.

- **Vulnerability Rank:** High

- **Currently Implemented Mitigations:**
    - **Shortcode Validation:** Custom emoji shortcodes are validated using a regular expression (`/^:[A-Za-z0-9-_]+:$/`) to ensure they follow a specific format.
    - **HTML Escaping for Other Text:** The `escapeHtml()` function is used for escaping other text content during formatting, but not for emoji values.

- **Missing Mitigations:**
    - **Emoji Value Sanitization:** No sanitization or output encoding is applied to the emoji mapping value in `TextFormatter.registerCustomEmojiMappings()` or during HTML generation for emoji nodes.
    - **Sanitize Emoji Values:** Implement sanitization or safe encoding of the emoji string, either during registration in `registerCustomEmojiMappings()` or before insertion into the DOM in `formatLine()`.
    - **Use Safe DOM Insertion:** Ensure that emoji values are inserted into the DOM safely, preventing HTML/script injection. Consider using `textContent` or a secure templating system.

- **Preconditions:**
    - The attacker must be able to supply a custom emoji mapping. This could be via repository configuration files, extension settings, or other mechanisms that allow user-provided emoji mappings.
    - The victim must load text (e.g., commit messages) that contains the malicious emoji shortcode.

- **Source Code Analysis:**
    - **File:** `web/textFormatter.ts`
        ```typescript
        public static registerCustomEmojiMappings(mappings: { shortcode: string, emoji: string }[]) {
            const validShortcodeRegExp = /^:[A-Za-z0-9-_]+:$/;
            for (let i = 0; i < mappings.length; i++) {
                if (validShortcodeRegExp.test(mappings[i].shortcode)) {
                    TextFormatter.EMOJI_MAPPINGS[mappings[i].shortcode.substring(1, mappings[i].shortcode.length - 1)] = mappings[i].emoji; // Unsanitized emoji value stored
                }
            }
        }

        private formatLine(line: TF.Node[]): string {
            const html: string[] = [];
            for (let i = 0; i < line.length; i++) {
                const node = line[i];
                switch (node.type) {
                    // ... other cases ...
                    case TF.NodeType.Emoji:
                        html.push(node.emoji); // Vulnerable line: Unsanitized emoji value pushed to HTML
                        break;
                    // ... other cases ...
                }
            }
            return html.join('');
        }
        ```
    - **Vulnerable Steps:**
        1. In `registerCustomEmojiMappings()`, the emoji value (`mappings[i].emoji`) is stored in `TextFormatter.EMOJI_MAPPINGS` without sanitization.
        2. In `formatLine()`, when processing an Emoji node, `node.emoji` (the unsanitized emoji value) is directly pushed into the `html` array, which is later joined and set as `innerHTML`.

- **Security Test Case:**
    1. **Define Malicious Emoji Mapping:** Prepare a custom emoji mapping with shortcode `:xss:` and emoji value `<img src=x onerror=alert("XSS")>`. Configure the extension to load this mapping (e.g., via settings or a configuration file if supported).
    2. **Register Emoji Mapping:** Ensure the extension calls `TextFormatter.registerCustomEmojiMappings()` with this malicious mapping.
    3. **Create Commit Message with Shortcode:** Create a commit message or text content that includes the shortcode `:xss:`.
    4. **Open Repository in Git Graph:** Open the repository in Git Graph to process the commit message.
    5. **Verify XSS:** Observe if an alert box appears when the commit message containing `:xss:` is rendered. This confirms the execution of the injected JavaScript and the stored DOM-based XSS vulnerability.