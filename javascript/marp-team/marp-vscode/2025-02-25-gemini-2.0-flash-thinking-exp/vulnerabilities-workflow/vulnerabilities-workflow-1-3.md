* Vulnerability 2: HTML Injection via Markdown Content

- Vulnerability name: HTML Injection via Markdown Content
- Description:
    1. An attacker crafts a malicious Marp Markdown file containing embedded HTML elements, including potentially `<script>` tags with JavaScript code.
    2. A victim user opens this malicious Marp Markdown file in VS Code with Marp for VS Code extension enabled.
    3. If the `markdown.marp.html` setting is set to `all`, the extension renders all HTML elements in the Markdown preview, including the malicious `<script>` tags.
    4. The JavaScript code within the injected `<script>` tags executes within the context of the Markdown preview.
    5. This could lead to various attacks, including stealing information from the VS Code environment (if accessible), performing actions on behalf of the user within the VS Code context, or redirecting the user to malicious websites.
- Impact:
    - High impact if `markdown.marp.html` is set to `all`. Arbitrary JavaScript execution within the VS Code preview context can lead to significant security breaches, potentially compromising the user's workspace or VS Code environment.
- Vulnerability rank: high (if `markdown.marp.html` is 'all')
- Currently implemented mitigations:
    - Workspace Trust: In untrusted workspaces, HTML elements in Marp Markdown are always ignored, regardless of the `markdown.marp.html` setting. This is a significant mitigation factor if Workspace Trust is enforced.
    - `markdown.marp.html` setting:  The setting allows users to control HTML rendering. The default is not 'all', which limits the risk if users do not explicitly enable full HTML rendering. The README mentions that only "selectivity HTML elements by Marp" are rendered by default, which suggests a built-in allowlist.
- Missing mitigations:
    - Content Sanitization: Even if `markdown.marp.html` is not 'all', and uses an allowlist, there should be robust sanitization of allowed HTML elements and attributes to prevent XSS or other HTML injection attacks.  It is not clear from the documentation if the "selectivity HTML elements" are properly sanitized.
- Preconditions:
    - The victim user must open a malicious Marp Markdown file.
    - For full HTML injection via `<script>` tags, the `markdown.marp.html` setting must be set to `all` and the workspace must be trusted. If set to default or 'allowed', the vulnerability might still be present depending on the "selectivity HTML elements by Marp" and if they are properly sanitized.
- Source code analysis:
    1. Review the code that processes the `markdown.marp.html` setting and handles HTML rendering in the Markdown preview. _Without direct code access, this is based on README.md description._
    2. Verify how the extension handles HTML content when `markdown.marp.html` is set to 'all', 'allowed' (default), or 'off'.
    3. Check if any HTML sanitization is performed before rendering, especially if 'allowed' mode still renders some HTML elements. Investigate the "Marp Core" and "allowlist.ts" mentioned in the README to understand the default HTML handling.
- Security test case:
    1. Create a Marp Markdown file with `marp: true` in the front-matter.
    2. Insert the following HTML code into the Markdown file:
       ```markdown
       ---
       marp: true
       ---

       <script>
         alert('XSS Vulnerability!');
       </script>

       # Test Slide
       ```
    3. Open the VS Code settings and set `markdown.marp.html` to `all`.
    4. Open the preview for the created Marp Markdown file.
    5. Observe if the alert box `'XSS Vulnerability!'` appears. If it does, it confirms HTML injection vulnerability when `markdown.marp.html` is set to `all`.
    6. Repeat steps 3-5, but with `markdown.marp.html` set to the default (or 'allowed' if that's a valid option).
    7. If the alert box still appears, investigate the "selectivity HTML elements" and if they are being sanitized. If the alert does not appear in default mode, the vulnerability is mitigated to some extent by the default setting, but still exists if user explicitly sets `markdown.marp.html` to `all`.