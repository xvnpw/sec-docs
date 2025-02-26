## Vulnerability List

- Arbitrary File Opening via JSDoc Links in Hover Information

Description:
The Angular Language Service processes JSDoc comments and converts `@link` tags into clickable links in hover information. These links use a custom command `angular.openJsDocLinkCommandId`. When a user clicks on such a link, the `openJsDocLinkCommand` in `client/src/commands.ts` is executed, which in turn uses `vscode.commands.executeCommand('vscode.open', vscode.Uri.parse(args.file), ...)`. If the `args.file` parameter, derived from the JSDoc `@link` target, is not properly validated and sanitized, a malicious actor could craft a JSDoc comment containing a link with a file URI pointing to a sensitive file on the user's system. Clicking this link would then cause VS Code to open the file, potentially exposing its content to the attacker if they can observe the user's screen or gain access to the VS Code instance.

Impact:
High. Arbitrary file opening can lead to information disclosure. An attacker could craft a malicious Angular component with JSDoc comments that, when hovered over, display links that, when clicked, open sensitive local files (e.g., `.bashrc`, private keys, etc.). While it does not directly lead to code execution, it can expose sensitive information.

Vulnerability Rank:
high

Currently Implemented Mitigations:
None. There is no input validation or sanitization for the `args.file` parameter in `openJsDocLinkCommand` or in `convertLinkTags` where the link is created.

Missing Mitigations:
Input validation and sanitization for the `args.file` parameter in `openJsDocLinkCommand` and for the URL generated from `@link` tags in `text_render.ts`.  Specifically, the `args.file` should be checked to ensure it is a safe URI and that it points to a file within the workspace or a designated safe location. A whitelist of allowed URI schemes (e.g., `http`, `https`, `file` with workspace restrictions) and path validation should be implemented.

Preconditions:
- The user must open a project with a malicious Angular component containing a crafted JSDoc comment with a malicious `@link`.
- The user must hover over a code element that triggers the display of the malicious JSDoc comment in the hover information.
- The user must click on the malicious link in the hover information.

Source Code Analysis:
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

Security Test Case:
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