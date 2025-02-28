### Vulnerability List for VS Code ES7+ React/Redux/React-Native/JS snippets

* Vulnerability Name: Malicious Prettier Configuration Execution
* Description:
    1. An attacker crafts a malicious workspace containing a Prettier configuration file (e.g., `.prettierrc.js` or `prettier.config.js`) designed to execute arbitrary code when Prettier is invoked.
    2. A user, with the "es7-react-js-snippets" extension installed and "prettierEnabled" option enabled, opens this malicious workspace in VSCode.
    3. The extension, during snippet formatting (triggered by user actions like using a snippet or on configuration changes that regenerate snippets), utilizes Prettier for code formatting.
    4. The `prettier.resolveConfig` function within `getPrettierConfig.ts` resolves and loads the malicious Prettier configuration from the workspace.
    5. When Prettier formats the snippet string, the malicious configuration executes arbitrary code within the VSCode extension's context.
* Impact:
    Arbitrary code execution within the VSCode extension's context. This can lead to:
    - Stealing sensitive information (workspace files, environment variables, VSCode API tokens).
    - Modifying workspace files.
    - Installing malicious extensions or tools.
    - Data exfiltration to external servers or establishing reverse shells.
* Vulnerability Rank: high
* Currently Implemented Mitigations:
    None. The extension directly uses Prettier's configuration resolution without any sanitization.
* Missing Mitigations:
    - Sanitize or validate Prettier configurations loaded from workspaces.
    - Implement a restricted Prettier execution environment or sandboxing.
    - Warn users about the risks of enabling Prettier integration when opening untrusted workspaces.
    - Provide an option to disable workspace configuration loading for Prettier.
* Preconditions:
    - User has the "es7-react-js-snippets" extension installed.
    - User has the "prettierEnabled" setting enabled in the extension's configuration.
    - User opens a malicious workspace containing a malicious Prettier configuration file (e.g., `.prettierrc.js`, `prettier.config.js`).
    - The extension performs snippet formatting, which can be triggered by using a snippet or changing extension settings.
* Source Code Analysis:
    1. `/code/src/helpers/getPrettierConfig.ts`:
        ```typescript
        import prettier, { Options } from 'prettier';

        import extensionConfig from './extensionConfig';

        let prettierConfig: prettier.Options | null;
        prettier
          .resolveConfig('', { editorconfig: true })
          .then((config) => (prettierConfig = config));

        const getPrettierConfig = (): Options => {
          const { prettierEnabled } = extensionConfig();

          return {
            parser: 'typescript',
            ...(prettierEnabled && prettierConfig),
          };
        };

        export default getPrettierConfig;
        ```
        - `prettier.resolveConfig('', { editorconfig: true })` is used to resolve Prettier configuration. This function inherently loads and resolves configuration files like `.prettierrc.js` and `prettier.config.js` from the workspace. If a malicious file is present, it will be loaded.
    2. `/code/src/helpers/formatters.ts`:
        ```typescript
        import prettier from 'prettier';

        import extensionConfig from './extensionConfig';
        import getPrettierConfig from './getPrettierConfig';
        import {
          replaceSnippetPlaceholders,
          revertSnippetPlaceholders,
        } from './snippetPlaceholders';

        export const formatSnippet = (snippetString: string) => {
          return extensionConfig().prettierEnabled
            ? prettier.format(snippetString, getPrettierConfig())
            : snippetString;
        };

        export const parseSnippet = (body: string | string[]) => {
          const snippetBody = typeof body === 'string' ? body : body.join('\n');

          return replaceSnippetPlaceholders(
            formatSnippet(revertSnippetPlaceholders(snippetBody)),
          );
        };
        ```
        - `formatSnippet` function calls `getPrettierConfig()` to retrieve the Prettier configuration and then uses `prettier.format(snippetString, getPrettierConfig())` to format the snippet. This is the point where the malicious Prettier configuration, if loaded, gets executed during the formatting process.
* Security Test Case:
    1. Create a new directory named `malicious-workspace`.
    2. Inside `malicious-workspace`, create a file named `prettier.config.js` with the following content:
        ```javascript
        module.exports = {
          semi: false,
          trailingComma: 'all',
          singleQuote: true,
          plugins: [
            {
              parsers: {
                typescript: parser => ({
                  ...parser,
                  parse: (...args) => {
                    // Malicious code execution - display an error message
                    const { window } = require('vscode');
                    window.showErrorMessage('Malicious Prettier Config Executed!');
                    return parser.parse(...args);
                  }
                })
              },
              format: (code) => code,
            }
          ]
        };
        ```
    3. Open VSCode and open the `malicious-workspace` directory.
    4. Ensure that the "es7-react-js-snippets" extension is installed and the "prettierEnabled" setting is set to `true` in the extension's settings.
    5. Open any JavaScript or TypeScript file within the `malicious-workspace`.
    6. Trigger snippet formatting. This can be achieved by:
        - Changing any setting of the extension in VSCode settings (which triggers `onDidChangeConfiguration` and snippet regeneration).
        - Using any snippet provided by the extension (e.g., type `rcc` and press Tab).
    7. Observe that an error message "Malicious Prettier Config Executed!" is displayed by VSCode. This confirms that the malicious code within `prettier.config.js` has been executed by the extension.