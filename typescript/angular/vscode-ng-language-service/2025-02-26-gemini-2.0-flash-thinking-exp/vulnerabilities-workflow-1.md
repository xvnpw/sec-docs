## Vulnerability List

- Vulnerability Name: Arbitrary File Opening via JSDoc Links in Hover Information

  - Description: The Angular Language Service processes JSDoc comments and converts `@link` tags into clickable links in hover information. These links use a custom command `angular.openJsDocLinkCommandId`. When a user clicks on such a link, the `openJsDocLinkCommand` in `client/src/commands.ts` is executed, which in turn uses `vscode.commands.executeCommand('vscode.open', vscode.Uri.parse(args.file), ...)`. If the `args.file` parameter, derived from the JSDoc `@link` target, is not properly validated and sanitized, a malicious actor could craft a JSDoc comment containing a link with a file URI pointing to a sensitive file on the user's system. Clicking this link would then cause VS Code to open the file, potentially exposing its content to the attacker if they can observe the user's screen or gain access to the VS Code instance.

  - Impact: High. Arbitrary file opening can lead to information disclosure. An attacker could craft a malicious Angular component with JSDoc comments that, when hovered over, display links that, when clicked, open sensitive local files (e.g., `.bashrc`, private keys, etc.). While it does not directly lead to code execution, it can expose sensitive information.

  - Vulnerability Rank: high

  - Currently Implemented Mitigations: None. There is no input validation or sanitization for the `args.file` parameter in `openJsDocLinkCommand` or in `convertLinkTags` where the link is created.

  - Missing Mitigations: Input validation and sanitization for the `args.file` parameter in `openJsDocLinkCommand` and for the URL generated from `@link` tags in `text_render.ts`.  Specifically, the `args.file` should be checked to ensure it is a safe URI and that it points to a file within the workspace or a designated safe location. A whitelist of allowed URI schemes (e.g., `http`, `https`, `file` with workspace restrictions) and path validation should be implemented.

  - Preconditions:
    - The user must open a project with a malicious Angular component containing a crafted JSDoc comment with a malicious `@link`.
    - The user must hover over a code element that triggers the display of the malicious JSDoc comment in the hover information.
    - The user must click on the malicious link in the hover information.

  - Source Code Analysis:
    1. In `/code/server/src/text_render.ts`, the `convertLinkTags` function processes JSDoc documentation.
    2. Inside `convertLinkTags`, when a `link` part is encountered, it constructs a command URI:
       ```typescript
       const command = `command:${OpenJsDocLinkCommandId}?${encodeURIComponent(JSON.stringify(args))}`;
       ```
       where `args` is of type `OpenJsDocLinkCommand_Args` and `OpenJsDocLinkCommandId` is `'angular.openJsDocLink'`. `args.file` comes directly from `currentLink.target.fileName` or `text` part of `@link` tag. There's no validation or sanitization of these values.
    3. In `/code/client/src/commands.ts`, the `openJsDocLinkCommand` is defined:
       ```typescript
       function openJsDocLinkCommand(): Command<OpenJsDocLinkCommand_Args> {
         return {
           id: OpenJsDocLinkCommandId,
           isTextEditorCommand: false,
           async execute(args) {
             return await vscode.commands.executeCommand(
                 'vscode.open', vscode.Uri.parse(args.file), <vscode.TextDocumentShowOptions>{...});
           },
         };
       }
       ```
       Here, `vscode.Uri.parse(args.file)` is used directly to parse the `file` string from the `args` and then `vscode.commands.executeCommand('vscode.open', ...)` is called without any validation of the parsed URI or the file path.

  - Security Test Case:
    1. Create a malicious Angular component (e.g., `vuln.component.ts`) in a test project.
    2. In the component, add a property with a JSDoc comment containing a malicious `@link` tag that points to a sensitive file on the system, for example, `file:///etc/passwd`.
       ```typescript
       export class VulnComponent {
         /**
          * @link file:///etc/passwd
          */
         sensitiveInfo;
       }
       ```
    3. Open this project in VS Code with the Angular Language Service extension enabled.
    4. Open the `vuln.component.ts` file in the editor.
    5. Hover over `sensitiveInfo` property.
    6. In the hover information, a link with the text "file:///etc/passwd" (or similar, depending on rendering) should be visible.
    7. Click on this link.
    8. Observe if VS Code attempts to open the `/etc/passwd` file in a new editor window. If it does, the vulnerability is confirmed.

- Vulnerability Name: Inadvertent Re‑Enablement of the Rename Override TS Plugin

  - Description:
    - The extension includes a TypeScript rename override plugin that is disabled by default.
    - However, if an attacker can force a user (for example, by tricking them into opening a compromised workspace) to modify workspace or user configuration files, they might cause this plugin to be re‑enabled.
    - Once activated, rename operations invoke the plugin’s logic (which delegates into Angular’s language service) without additional validation, potentially processing malicious rename requests.

  - Impact:
    - An attacker may trigger arbitrary code execution within the VSCode process. This could lead to unsanctioned file modifications, data exfiltration, or even the installation of further malicious components.

  - Vulnerability Rank: High

  - Currently Implemented Mitigations:
    - The plugin is disabled by default in the extension’s configuration.
    - Documentation clearly states that the override is not active under normal usage.

  - Missing Mitigations:
    - There is no enforced runtime check that prevents an external attacker (via workspace or user configuration manipulation) from re‑enabling the plugin.
    - Additional input validation/sanitization in the rename request processing is absent.

  - Preconditions:
    - The attacker must be able to influence workspace or user settings (for example, by luring the user into opening a pre‑configured or compromised workspace).

  - Source Code Analysis:
    - In the rename plugin source (for example, in the TS rename override module), the factory simply forwards rename operations into Angular’s language service without extra checks.
    - Since the plugin exists in the codebase and is only disabled by configuration, a manipulated configuration can load it and allow rename requests to flow un‑filtered.

  - Security Test Case:
    - Run VSCode with the extension installed in a controlled environment.
    - Modify the workspace or user settings file (or open a workspace with malicious settings) so that the rename override plugin is force‑enabled.
    - Initiate a rename operation using an identifier that includes maliciously crafted characters.
    - Monitor the behavior (via logs or debugger) for evidence that the plugin improperly processes the input, indicating the potential for arbitrary command execution.

- Vulnerability Name: Untrusted TypeScript Package Loading via Workspace Dependencies

  - Description:
    - The language service determines which TypeScript library to load by checking (in order) user‑configured overrides (such as the “typescript.tsdk” setting), then the bundled trusted version, and finally falling back to a TypeScript package found in the workspace’s “node_modules” directory.
    - If an attacker is able to introduce a malicious (though correctly named and versioned) TypeScript package into a workspace and if no trusted “tsdk” is set, the extension may load this untrusted package.
    - The malicious package code might then trigger arbitrary command or code execution within the extension process.

  - Impact:
    - Exploitation would allow an attacker to execute arbitrary code within the VSCode extension. This could result in file modifications, data exfiltration, lateral movement, or installation of additional malicious software.

  - Vulnerability Rank: High

  - Currently Implemented Mitigations:
    - The extension ships with a bundled and trusted version of TypeScript that is used by default.
    - Users are advised (typically via documentation and settings recommendations) to explicitly set a trusted “typescript.tsdk” path, thereby avoiding reliance on a potentially compromised workspace package.

  - Missing Mitigations:
    - No runtime integrity verification (such as cryptographic signature or hash checks) is performed on workspace‑provided TypeScript packages.
    - There is no explicit user prompt or warning when falling back to a workspace version of TypeScript.

  - Preconditions:
    - The attacker must control or supply a compromised TypeScript package into the workspace’s “node_modules” directory, and the user must not have over‑ridden the default behavior by specifying a trusted “typescript.tsdk”.

  - Source Code Analysis:
    - In the module responsible for resolving TypeScript packages (located in the common resolver files and version provider), an ordered lookup is performed: first checking for a user‑provided “tsdk” option, then using the bundled version, and finally falling back to a package discovered in the workspace.
    - In the fallback code path, there are no integrity checks, so if an attacker supplies a malicious package that meets the expected naming and version requirements, it will be loaded.

  - Security Test Case:
    - Create a controlled workspace and insert into its “node_modules” directory a malicious TypeScript package that matches the package name and version expectations.
    - Ensure that no trusted “typescript.tsdk” setting is provided.
    - Open the compromised workspace in VSCode with the extension enabled.
    - Trigger typical language service operations (such as auto‑completion or “go to definition”) and examine logs or behavior for abnormal actions or evidence of injected code execution.

- Vulnerability Name: Regular Expression Denial of Service (ReDoS) in JSDoc Link Parsing

  - Description: The `asPlainTextWithLinks` function in `/code/server/src/text_render.ts` uses a regular expression to parse JSDoc `@link` tags. This regex `/(?<link>(?<url>(https?:\/\/[^\s|}]+))(?<text>\|[^\s|}]+)?)(?<trail>.*)/ms` is vulnerable to ReDoS. An attacker can craft a JSDoc comment with a specially crafted `@link` tag that causes the regex engine to backtrack excessively, leading to a denial of service. Specifically, a long link text combined with the greedy `(?<trail>.*)` can trigger this vulnerability.

  - Impact: Processing a file with a malicious JSDoc comment can cause the Angular Language Service extension to become unresponsive, leading to a denial of service within VSCode. This can disrupt the developer's workflow and potentially impact other VSCode functionalities if the extension becomes unstable or consumes excessive resources.

  - Vulnerability Rank: high

  - Currently implemented mitigations: No mitigations are currently implemented in the provided code.

  - Missing mitigations:
    - Implement a non-greedy regular expression for parsing JSDoc links. For example, change `(?<trail>.*)` to `(?<trail>.*?)`. However, thorough testing is needed to ensure this fully mitigates ReDoS and doesn't introduce new issues.
    - Limit the complexity of JSDoc link parsing by setting limits on the length of link URLs and link texts.
    - Consider using a parser-based approach instead of regular expressions for parsing JSDoc links to have more control over parsing complexity and prevent ReDoS vulnerabilities.

  - Preconditions:
    - The attacker needs to be able to influence the content of TypeScript files that are processed by the Angular Language Service extension. This could be through contributing to a project, providing code snippets, or in scenarios where the extension processes external or user-provided code.
    - The VSCode editor with the Angular Language Service extension must be actively processing the file containing the malicious JSDoc comment (e.g., during code completion, hover, or diagnostics).

  - Source code analysis:
    - Vulnerable code is located in `/code/server/src/text_render.ts` within the `asPlainTextWithLinks` function.
    - The function uses the regex `/(?<link>(?<url>(https?:\/\/[^\s|}]+))(?<text>\|[^\s|}]+)?)(?<trail>.*)/ms` to parse the content of `@link` tags in JSDoc comments.
    - The regex contains a potentially problematic group `(?<trail>.*)` which is greedy and can match any character zero or more times.
    - When processing a JSDoc comment with a long `@link` tag, especially with a long link text (after the `|`), the regex engine might enter a state of excessive backtracking due to the greedy `(?<trail>.*)` trying to match as much as possible, leading to ReDoS.

    ```typescript
    export function asPlainTextWithLinks(
        parts: tss.SymbolDisplayPart[], openJsDocLink: OpenJsDocLinkFn, plainText = parts.map(p => p.text).join('')):
        string {
      const textParts = plainText.split(/{@(linkcode|linkplain|link) /); // Split by @link tags
      if (textParts.length === 1) return plainText;

      let res = '';
      res += textParts[0];
      for (let i = 1; i < textParts.length; i += 2) {
        const command = textParts[i]; // 'linkcode', 'linkplain', or 'link'
        const linkRegEx = /(?<link>(?<url>(https?:\/\/[^\s|}]+))(?<text>\|[^\s|}]+)?)(?<trail>.*)/ms; // Vulnerable Regex
        const linkMatch = linkRegEx.exec(textParts[i + 1]); // Execute regex on link content

        // ... (rest of the code)
      }
      return res;
    }
    ```

  - Security test case:
    1. Create a new TypeScript file, for example, `redos_test.ts`.
    2. Add the following code to `redos_test.ts`:
        ```typescript
        /**
         *  {@link http://example.com/foo|aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa}
         */
        function vulnerableFunction() {
            // This function has a JSDoc comment with a long @link tag that can trigger ReDoS.
        }

        vulnerableFunction();
        ```
    3. Open `redos_test.ts` in VSCode with the Angular Language Service extension enabled.
    4. Trigger JSDoc rendering for `vulnerableFunction`. This can be done by hovering over `vulnerableFunction` or by triggering code completion that shows the JSDoc.
    5. Observe the behavior of VSCode. If the vulnerability is triggered, VSCode might become unresponsive or experience a significant delay. Monitor CPU usage to confirm high CPU consumption during this period, indicating potential ReDoS.
    6. To further confirm, try increasing the length of the 'a' sequence in the `@link` tag. A longer sequence is more likely to trigger the ReDoS vulnerability and make the unresponsiveness more noticeable.