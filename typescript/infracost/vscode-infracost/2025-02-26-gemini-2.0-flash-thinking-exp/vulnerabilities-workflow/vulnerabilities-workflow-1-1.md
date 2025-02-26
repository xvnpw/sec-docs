* Vulnerability 1
- Vulnerability name: Potential Template Injection via Infracost CLI Output
- Description: The Infracost VS Code extension uses Handlebars templates to render cost breakdowns in webviews. The data rendered in these templates originates from the output of the `infracost` CLI, which is parsed as JSON. If an attacker could influence the `infracost` CLI output, they could inject malicious HTML or JavaScript into the webview by crafting malicious resource names, cost component names, units, or prices. This is possible because the Handlebars templates might not be properly escaping HTML entities in these fields before rendering them in the webview.
- Impact: Successful template injection allows arbitrary JavaScript execution within the VS Code webview context. This could lead to:
    - Stealing sensitive information from the VS Code workspace (e.g., environment variables, file contents, tokens).
    - Performing actions on behalf of the user within VS Code or other extensions.
    - Redirecting the user to malicious websites.
    - Displaying misleading information in the cost breakdown webview.
- Vulnerability rank: high
- Currently implemented mitigations: None. The code uses CLI output directly in templates without HTML escaping.
- Missing mitigations: Implement HTML escaping for all data from the Infracost CLI output before rendering it in Handlebars templates. Utilize Handlebars built-in escaping mechanisms for fields like resource names, cost component names, units, and prices.
- Preconditions:
    - An attacker needs to be able to influence the output of the `infracost` CLI. This could potentially be achieved by compromising Infracost backend or CLI, or by crafting specific Terraform configurations.
    - A user must open a cost breakdown webview in VS Code.
- Source code analysis:
    - `src/cli.ts`: Defines `CLI.exec` to execute the infracost CLI and parse JSON output (`infracostJSON.RootObject`).
    - `src/workspace.ts`: Uses `CLI.exec` to run `infracost breakdown`, processes the JSON output, and creates `Project`, `File`, and `Block` objects.
    - `src/block.ts`: `Block.display()` renders webviews using `this.template(this)`, passing the `Block` object as context.
    - `src/template.ts`: Compiles Handlebars templates from `.hbs` files.
    - Templates in `src/templates/*.hbs` (e.g., `block-output.hbs`, `cost-component-row.hbs`) use Handlebars expressions like `{{resource.name}}`, `{{costComponent.name}}`, `{{costComponent.unit}}`, `{{costComponent.price}}` to display data. These expressions, by default, do not perform HTML escaping.
    - **Vulnerability Point:** Handlebars templates lack explicit HTML escaping for CLI output data. If `infracostJSON` data contains HTML, it will be rendered as HTML in the webview, enabling template injection.
- Security test case:
    1. **Modify CLI Output (for testing):** In `src/cli.ts`, within `CLI.exec`, add a conditional block to simulate malicious CLI output when `args[0] === 'breakdown'`. This simulated output should include a malicious resource name containing JavaScript code, like `<img src='x' onerror='alert("Template Injection Vulnerability!")'>`.
    2. **Rebuild Extension:** Recompile the VS Code extension after modifying `src/cli.ts`.
    3. **Open Terraform Project:** Open any Terraform project in VS Code.
    4. **Trigger Infracost:**  Run Infracost by saving a Terraform file or refreshing the project tree.
    5. **Open Webview:** Open the cost breakdown webview for any resource (via code lens or tree view).
    6. **Verify Vulnerability:** An alert box with "Template Injection Vulnerability!" should appear in the webview, indicating successful JavaScript injection.
    7. **Cleanup:** Revert changes in `src/cli.ts` and rebuild the extension to restore normal functionality.