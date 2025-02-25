- **Vulnerability Name:** Path Traversal in Custom Icon Associations
  **Description:**
  The extension lets users configure custom icon associations via their settings (for example, by mapping a file name or extension to a custom SVG located via a relative path). The documentation instructs that custom icons must be placed under a given folder (the extension’s distribution or within the user’s `.vscode/extensions` folder). However, if the code that loads these custom SVG files does not properly validate or sanitize the user‐supplied file paths, an attacker could supply a path containing directory traversal sequences (e.g. `"../../../../etc/passwd"`). When the extension constructs the file path to load the icon, it may resolve to an unintended system file or sensitive resource.
  **Impact:**
  - Arbitrary file read and disclosure of sensitive information from the local file system.
  - Unauthorized retrieval of arbitrary file content if the icon engine (or an associated rendering component) processes and displays the file’s content in the UI without proper checks.
  **Vulnerability Rank:** High
  **Currently Implemented Mitigations:**
  - The documentation instructs users to only use custom icons placed inside designated directories.
  - There is an expectation (by convention) that the user’s configuration follows the documented rules; however, no runtime check is performed.
  **Missing Mitigations:**
  - No programmatic validation (e.g. resolving the absolute path and enforcing a whitelist) is found in the configuration handling.
  - The code does not validate that the resolved path for a custom icon remains within permitted directories.
  **Preconditions:**
  - The attacker must be able to trick a user into applying a custom icon association with a malicious relative path through settings. For example, by convincing user to import malicious settings or contributing to a public settings repository used by the user.
  - The extension must use the raw user‑supplied string to construct file URLs without enforcing directory boundaries.
  **Source Code Analysis:**
  - The README and module documentation show that custom icon associations are configured in settings (for example, mapping `"fileName.ts": "../../icons/sample"`).
  - There is no visible sanitization routine or check that rejects paths containing traversal sequences.
  - When the extension later reads this configuration to load the SVG file, it likely simply concatenates the user‑provided path with its base folder—thus allowing directory traversal if not normalized.
  **Security Test Case:**
  1. Open the user settings (e.g. `settings.json`) of a publicly available VS Code instance with the extension installed.
  2. Add a custom association using a path designed to escape the allowed directory:
     ```json
     "material-icon-theme.files.associations": {
         "sensitive": "../../../../etc/passwd"
     }
     ```
  3. Create a file named `sensitive` in the opened workspace.
  4. Observe if the icon for the `sensitive` file is loaded. If the vulnerability exists, the extension might attempt to load and display the contents of `/etc/passwd` as an icon, or generate an error indicating file access outside of permitted directories. An attacker might not directly see `/etc/passwd` content as an icon, but monitoring file access logs of the VS Code instance or observing error messages could confirm the path traversal attempt.

---

- **Vulnerability Name:** Malicious SVG Injection via Icon Cloning
  **Description:**
  The extension supports “cloning” of existing icons and recoloring them via configuration (for example, by specifying a base icon and new color values in the settings). The cloning logic is described as working by replacing color attribute strings in the SVG file. If this process is performed by simple textual replacements without proper sanitization, then a maliciously crafted SVG could embed dangerous payloads (such as `<script>` tags or JavaScript event handlers). When the cloned (or recolored) SVG is subsequently rendered in the extension’s UI or as part of a web project (via the exposed npm module), the unsanitized SVG markup might execute embedded code in the context of the VS Code environment.
  **Impact:**
  - Execution of arbitrary JavaScript in the context of the user’s editor – potentially leading to data exfiltration, unauthorized actions, or further compromise of the user’s system.
  - Compromise of UI integrity and loss of user trust if malicious icons are rendered in place of trusted ones.
  **Vulnerability Rank:** High
  **Currently Implemented Mitigations:**
  - The documentation advises that all SVG icons should be “fully vectorized” (i.e. not contain embedded base64 images) and that only approved Material Design colors should be used.
  - There appears to be an expectation that icons come from a trusted source.
  **Missing Mitigations:**
  - No runtime sanitization or validation of the SVG content is performed before it is processed for cloning and recoloring.
  - The cloning mechanism likely relies on simple string manipulation which does not strip dangerous elements or attributes.
  **Preconditions:**
  - An attacker must be able to supply a custom SVG icon (either by convincing a user to apply a configuration change) that includes malicious payloads (for example, an `<svg>` file with an embedded `<script>` tag or an `onload` attribute). This could be achieved by tricking user into importing malicious settings or contributing to a public settings repository used by the user.
  - The extension must process this malicious SVG using its cloning/recoloring mechanism without applying security filters.
  **Source Code Analysis:**
  - The README (and related documentation in the repository) describes the cloning approach as “simply using the shape of the icon” and “adjusting its color” by replacing color definitions.
  - There is no mention of a sanitization step that would inspect and remove scripting or event handler attributes from the SVG markup.
  - If an attacker’s SVG is processed in this way, the dangerous markup will be preserved in the final manifest used by the extension.
  **Security Test Case:**
  1. Create a custom SVG file with a malicious payload and host it on a publicly accessible web server. For example, create `malicious.svg` with the following content and upload it to `http://attacker.com/malicious.svg`:
     ```xml
     <svg xmlns="http://www.w3.org/2000/svg">
       <rect width="16" height="16" fill="#FF0000" onload="alert('XSS')" />
     </svg>
     ```
  2. In the user settings of a publicly available VS Code instance with the extension installed, configure a custom icon association that uses this SVG file via a URL:
     ```json
     "material-icon-theme.files.associations": {
         "malicious_file": "http://attacker.com/malicious.svg"
     }
     ```
  3. Open a file named `malicious_file` in the opened workspace.
  4. Observe whether the malicious code (in this example, an alert) is executed when the icon is rendered. If an alert box appears with 'XSS', it confirms that the JavaScript code within the SVG has been executed, demonstrating the vulnerability.