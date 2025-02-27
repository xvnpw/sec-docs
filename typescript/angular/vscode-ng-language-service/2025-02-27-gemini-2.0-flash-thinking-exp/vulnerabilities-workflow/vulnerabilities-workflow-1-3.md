## Vulnerability List

### Vulnerability 1: Potential XSS via Maliciously Crafted JSDoc @link Tag in Hover Information

- Description:
    1. An attacker crafts a malicious Angular component with a JSDoc comment containing a specially crafted `@link` tag.
    2. This `@link` tag includes a javascript: URI, which is intended to execute arbitrary JavaScript code when the link is rendered in VS Code's hover information.
    3. A user opens a project containing this malicious component in VS Code with the Angular Language Service extension enabled.
    4. The user hovers over a symbol in the component's template or TypeScript code that triggers the display of the JSDoc comment containing the malicious `@link` tag.
    5. VS Code renders the hover information, and due to insufficient sanitization of the `href` attribute in the markdown link generated from the `@link` tag, the javascript: URI is executed, leading to potential XSS.

- Impact:
    - Critical
    - Arbitrary JavaScript code execution within the user's VS Code environment when hovering over code elements.
    - This could allow an attacker to perform actions such as stealing credentials, accessing local files, or injecting further malicious content into the workspace.

- Vulnerability rank: critical

- Currently implemented mitigations:
    - The code in `server/src/text_render.ts` uses `encodeURIComponent` for parts of the URI, which provides some level of protection against trivial injection attempts.
    - The code also uses regex to replace links and process inline tags.

- Missing mitigations:
    - Lack of proper sanitization of the `href` attribute in the markdown link, specifically when handling javascript: URIs.
    - The `convertLinkTags` function in `server/src/text_render.ts` is not robust enough to prevent javascript: URI injection.

- Preconditions:
    - The user must open a workspace containing a malicious Angular component.
    - The malicious component must contain a JSDoc comment with a crafted `@link` tag.
    - The user must hover over a code element that triggers the display of this JSDoc comment.

- Source code analysis:
    1. **File:** `/code/server/src/text_render.ts`
    2. **Function:** `convertLinkTags(documentation, getScriptInfo)`
    3. This function processes JSDoc comments and converts `@link` tags into markdown links.
    4. The relevant code snippet:
    ```typescript
    function convertLinkTags(
        documentation: tss.SymbolDisplayPart[]|undefined|string,
        getScriptInfo: (fileName: string) => tss.server.ScriptInfo | undefined): string {
      // ...
      case 'link':
        if (currentLink) {
          if (currentLink.target) {
            // ...
            const command =
                `command:${OpenJsDocLinkCommandId}?${encodeURIComponent(JSON.stringify(args))}`;

            const linkText = currentLink.text ?
                currentLink.text :
                escapeMarkdownSyntaxTokensForCode(currentLink.name ?? '');
            out.push(`[${currentLink.linkcode ? '`' + linkText + '`' : linkText}](${command})`);
          } else {
            const text = currentLink.text ?? currentLink.name;
            if (text) {
              if (/^https?:/.test(text)) {
                const parts = text.split(' ');
                if (parts.length === 1) {
                  out.push(parts[0]);
                } else if (parts.length > 1) {
                  const linkText = escapeMarkdownSyntaxTokensForCode(parts.slice(1).join(' '));
                  out.push(
                      `[${currentLink.linkcode ? '`' + linkText + '`' : linkText}](${parts[0]})`);
                }
              } else {
                out.push(escapeMarkdownSyntaxTokensForCode(text));
              }
            }
          }
          currentLink = undefined;
        } else {
          currentLink = {linkcode: part.text === '{@linkcode '};
        }
        break;
      // ...
    ```
    5. The code checks if the link `text` starts with `https?:` but doesn't prevent other URI schemes like `javascript:`.
    6. The `escapeMarkdownSyntaxTokensForCode` function only escapes backticks and doesn't sanitize the URL itself.
    7. By crafting a JSDoc comment with `{@link javascript:alert('XSS')} Malicious Link }`, an attacker can inject javascript: URI.

- Security test case:
    1. Create a new Angular component file (e.g., `vuln.component.ts`) in a test Angular project.
    2. Add the following content to `vuln.component.ts`:
    ```typescript
    import { Component } from '@angular/core';

    /**
     * @link javascript:alert('XSS') Malicious Link
     */
    @Component({
        selector: 'vuln-component',
        template: '<div></div>',
    })
    export class VulnComponent {
    }
    ```
    3. Open the `vuln.component.ts` file in VS Code with the Angular Language Service extension.
    4. In the `vuln.component.ts` file, hover over the `VulnComponent` class name in the `@Component` decorator.
    5. Observe the hover information. If the vulnerability exists, clicking on "Malicious Link" in the hover tooltip will execute the JavaScript code `alert('XSS')`.
    6. A successful test case will show an alert dialog in VS Code when the link is clicked.