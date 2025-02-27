## Vulnerability Report

- **Vulnerability: DOM–based Cross–Site Scripting (XSS) in the Find Widget**
  - **Description:**
    The Git Graph View’s find widget (implemented in “web/findWidget.ts”) highlights matching text by taking substrings of text nodes and inserting them into new span elements via the helper method `createMatchElem()`. This helper sets the innerHTML of the span directly from such substrings without any output sanitization. An attacker who is able to inject a malicious payload into Git commit data (for example, by crafting a commit message containing HTML/JavaScript code such as `<img src=x onerror=alert(1)>`) can cause that payload to be executed when the find widget processes and highlights the matching text.
    *Step by step triggering scenario:*
    1. An attacker creates or contributes to a Git repository with one or more commits whose commit data (e.g. commit messages, branch names, or tags) contains a malicious payload including HTML/JavaScript code.
    2. A victim user loads this malicious repository in Git Graph.
    3. The victim opens the find widget (via its keybinding or UI button) and enters a search term that causes the widget to process portions of the compromised commit data.
    4. The unsanitized substring (containing the malicious payload) is inserted via innerHTML into the DOM, causing the browser to interpret and execute the payload.
  - **Impact:**
    Arbitrary script execution in the context of the extension window may allow an attacker to access internal VS Code APIs or data, modify extension behavior, or otherwise compromise both the extension and possibly the host editor’s environment.
  - **Vulnerability Rank:**
    **High**
  - **Currently Implemented Mitigations:**
    – The find widget code directly assigns unsanitized substrings to innerHTML in the helper method `createMatchElem()`.
    – There is no applied output encoding or alternative safe DOM–insertion method used when formatting the highlighted text.
  - **Missing Mitigations:**
    – Apply proper output encoding/sanitization (for example, using textContent instead of innerHTML or a secure HTML templating system) when inserting user–controlled text into the DOM.
    – Avoid directly using innerHTML for any content—even indirectly sourced from commit data.
  - **Preconditions:**
    – An attacker must be able to control a portion of the commit data (such as commit messages or branch/tag names) that later appears in the Git Graph View.
    – The victim loads a repository containing the malicious data and then uses the find widget so that the compromised text is processed.
  - **Source Code Analysis:**
    – In “web/findWidget.ts”, the helper method is defined as:
      ```ts
      private static createMatchElem(text: string) {
          const span = document.createElement('span');
          span.className = CLASS_FIND_MATCH;
          span.innerHTML = text;
          return span;
      }
      ```
    – When a search match is found (for example, in the `findMatches()` method), the substring extracted from the commit data is passed to `createMatchElem()`. Since no sanitization is applied before setting innerHTML, any injected payload is rendered and executed.
  - **Security Test Case:**
    1. Create (or contribute to) a test Git repository containing a commit with a message that includes a payload such as `<img src=x onerror=alert(1)>`.
    2. Open this repository in Git Graph within VS Code so that the commit data is rendered.
    3. Open the find widget (using its keybinding or UI control) and enter a search term that matches part of the malicious payload.
    4. Verify that when the widget highlights the matching text, the browser executes the payload (for example, an alert is displayed), confirming the XSS vulnerability.

- **Vulnerability: Stored DOM–Based Cross–Site Scripting (XSS) via Custom Emoji Mappings in TextFormatter**
  - **Description:**
    The extension’s text formatter (defined in “web/textFormatter.ts”) not only processes plain text, commit hashes, URLs, and markdown formatting but also supports custom emoji mappings. The public method `TextFormatter.registerCustomEmojiMappings()` accepts externally–provided mappings where each mapping consists of a shortcode (for example, `:smile:`) and an associated emoji string. Although the shortcodes are validated with a regular expression (ensuring the format matches `/^:[A-Za-z0-9-_]+:$/`), the emoji values themselves are not sanitized. Later, when formatting text that contains an emoji shortcode, the formatter checks for a matching entry in `TextFormatter.EMOJI_MAPPINGS` and, if found, creates an Emoji node. During the HTML generation phase in the `formatLine()` method, the emoji value is inserted into the output using:
    ```ts
    case TF.NodeType.Emoji:
        html.push(node.emoji);
        break;
    ```
    Because no output encoding is performed on `node.emoji`, an attacker who supplies a custom mapping with a malicious payload (for example, `<img src=x onerror=alert(1)>`) will have that payload rendered directly in the DOM when the associated shortcode is processed.
    *Step by step triggering scenario:*
    1. An attacker supplies a custom emoji mapping (via a repository configuration file or extension setting that supports custom emoji mappings) where the shortcode is valid (for example, `:xss:`) and the associated emoji value is malicious HTML/JavaScript code (for example, `<img src=x onerror=alert("XSS")>`).
    2. The extension calls `TextFormatter.registerCustomEmojiMappings()`, which accepts and stores this mapping in the `TextFormatter.EMOJI_MAPPINGS` object without sanitizing the emoji value.
    3. Later, when a commit message or other text processed by TextFormatter contains the custom emoji shortcode (e.g. `:xss:`), the formatter creates an Emoji node using the unsanitized emoji value.
    4. During HTML generation, the code directly appends the emoji value into the string that is set via innerHTML, causing the browser to interpret and execute the malicious payload.
  - **Impact:**
    The unsanitized insertion of externally–provided emoji values allows arbitrary script execution in the extension’s context. This may lead to compromise of sensitive data, manipulation of the Git Graph interface, and abuse of internal VS Code APIs.
  - **Vulnerability Rank:**
    **High**
  - **Currently Implemented Mitigations:**
    – The custom emoji mapping’s shortcode is validated to match the expected format (`:^:[A-Za-z0-9-_]+:$`), ensuring only alphanumeric characters, hyphens, and underscores are allowed between the colons.
    – All other text content in formatting routines is passed through the `escapeHtml()` function where appropriate.
  - **Missing Mitigations:**
    – There is no sanitization or output encoding applied to the emoji mapping value in the `TextFormatter.registerCustomEmojiMappings()` method or during HTML generation for emoji nodes.
    – A proper mitigation would include sanitizing (or safely encoding) the emoji string—either during registration or before insertion into the DOM—to ensure that no HTML or script can be injected.
  - **Preconditions:**
    – The attacker must be able to supply a custom emoji mapping. This might be achieved if the extension supports loading emoji mappings from a repository configuration file or from user–provided settings that are not further sanitized.
    – The victim must load text (such as commit messages) that includes the aforementioned emoji shortcode.
  - **Source Code Analysis:**
    1. In the `TextFormatter.registerCustomEmojiMappings()` method in “web/textFormatter.ts”, each supplied mapping is validated only on the shortcode format:
       ```ts
       const validShortcodeRegExp = /^:[A-Za-z0-9-_]+:$/;
       for (let i = 0; i < mappings.length; i++) {
           if (validShortcodeRegExp.test(mappings[i].shortcode)) {
               TextFormatter.EMOJI_MAPPINGS[mappings[i].shortcode.substring(1, mappings[i].shortcode.length - 1)] = mappings[i].emoji;
           }
       }
       ```
       No sanitization is applied to the emoji value (`mappings[i].emoji`).
    2. Later, in `formatLine()`, when a match is found for an emoji shortcode, the formatter creates a node of type `TF.NodeType.Emoji` with the stored emoji value from `TextFormatter.EMOJI_MAPPINGS`.
    3. Finally, during HTML generation, the switch case for `TF.NodeType.Emoji` does not invoke any escaping (unlike other node types) and directly pushes the emoji value into the HTML:
       ```ts
       case TF.NodeType.Emoji:
           html.push(node.emoji);
           break;
       ```
       This allows any malicious HTML/JavaScript in the emoji value to be rendered and executed.
  - **Security Test Case:**
    1. Prepare a custom emoji mapping (for example, via an appropriate configuration file or settings input) with the shortcode `:xss:` and set its emoji value to `<img src=x onerror=alert("XSS")>`.
    2. Ensure that the extension calls `TextFormatter.registerCustomEmojiMappings()` with this mapping.
    3. Create a commit message or text content that contains the shortcode `:xss:`.
    4. Open the repository in Git Graph so that the text formatter processes the commit message.
    5. Verify that the rendered output includes the malicious HTML, and that the payload is executed (for example, an alert box appears), confirming the XSS vulnerability.