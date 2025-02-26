- **Vulnerability Name:** Cross‑Site Scripting (XSS) in Exported HTML

  - **Description:**
    An attacker can craft a malicious markdown file containing raw HTML with embedded JavaScript (for example, an image tag with an onerror handler or an inline script). When a victim uses the “Print Markdown to HTML” command, the extension converts the markdown to HTML without clear evidence of sanitizing the embedded HTML. In this scenario, the malicious payload is carried into the exported HTML file. When the victim later opens that HTML file in a regular web browser—which does not enforce the same sandboxing as VS Code’s preview—the injected script runs with the privileges of the page, potentially stealing data or running further malicious commands.
    **Step‑by-step Trigger:**
    1. The attacker creates a markdown file that includes a heading, some benign markdown content, and a section with embedded HTML such as:
       ```markdown
       # Sample Document

       Here is an image:
       <img src="x" onerror="alert('XSS Attack!')">

       Or even an inline script:
       <script>alert('Injected!')</script>
       ```
    2. The attacker distributes this file (for example, by uploading it to a repository or sharing it via email).
    3. A victim opens the markdown file in VS Code and uses the “Print Markdown to HTML” command.
    4. The extension converts the file to HTML and saves it without additional sanitization of the raw HTML content.
    5. When the victim opens the exported HTML file in a web browser, the embedded JavaScript executes.

  - **Impact:**
    - Execution of arbitrary JavaScript in the context of the browser where the HTML file is viewed.
    - Attackers could steal sensitive data, hijack sessions, or install further malware.
    - The risk is particularly relevant if users share exported HTML files or use them in less secure environments.

  - **Vulnerability Rank:** High

  - **Currently Implemented Mitigations:**
    - The extension leverages VS Code’s built‑in markdown preview conversion, which in its live preview may apply some internal safe‑rendering policies.
    - However, the documentation does not specify that the exported HTML is sanitized additionally, and the export process is designed to “look the same as inside VS Code.”

  - **Missing Mitigations:**
    - A dedicated sanitization process (for example, using a robust markdown‑to‑HTML converter with proper XSS filtering) during export.
    - Implementation of a strict Content Security Policy (CSP) in the exported HTML to prevent execution of inline scripts.
    - Clear separation of trusted versus untrusted sources when handling raw HTML in markdown documents.

  - **Preconditions:**
    - The attacker must be able to provide or convince a user to open a malicious markdown file.
    - The victim must use the “Print Markdown to HTML” feature and subsequently open the generated HTML in a standard web browser without additional security controls.

  - **Source Code Analysis:**
    - The README and documentation files describe the “Print Markdown to HTML” feature without mentioning explicit HTML sanitization.
    - The exported HTML is meant to mimic the VS Code preview (which is sandboxed) but does not appear to apply additional filtering when saved as a stand‑alone file.
    - While the underlying conversion code is not shown in the provided files, the absence of any documented sanitization steps and the advice to “print the exported HTML to PDF with browser (e.g. Chrome)” indicate that the exported HTML is handled as pure output and is therefore susceptible to embedded malicious code.

  - **Security Test Case:**
    1. Prepare a markdown file (e.g., `malicious.md`) containing the following content:
       ```markdown
       # Test Page

       This is a test of HTML export.

       <img src="x" onerror="alert('XSS triggered!')">
       <script>alert('Injected script!');</script>
       ```
    2. Open this file in VS Code with the extension installed.
    3. Run the command “Print Markdown to HTML” from the Command Palette.
    4. Save the resulting HTML file.
    5. Open the exported HTML file in a standard web browser.
    6. Observe whether the browser executes the JavaScript (for example, an alert popup appears).
       _If the scripts are executed, the vulnerability is confirmed._

---

- **Vulnerability Name:** Insecure Remote Script Execution in CI Pipeline

  - **Description:**
    The GitHub Actions workflows (both in `main.yml` and `test.yml`) include a step that downloads an external shell script using curl and pipes it directly to the shell. Specifically, the step downloads the wasm‑pack installer script from
    ```
    curl https://rustwasm.github.io/wasm-pack/installer/init.sh -sSf | sh
    ```
    This “curl | sh” pattern means that the CI runner immediately executes whatever content is fetched—without performing any integrity or signature verification. Should an attacker compromise the remote script source or successfully execute a man‑in‑the‑middle (MITM) attack against the CI runner’s HTTPS connection, malicious code could be injected and executed within the CI environment.
    **Step‑by-step Trigger:**
    1. An attacker finds a way to compromise the remote host or intercept the HTTPS connection to `rustwasm.github.io`, serving a malicious version of `init.sh`.
    2. When the CI workflow executes, the compromised script is downloaded and piped directly to the shell.
    3. The malicious script executes within the CI runner, potentially altering the environment, exfiltrating build secrets, or modifying the build artifacts.

  - **Impact:**
    - Full compromise of the CI/CD pipeline, leading to the possibility of injecting malicious code into the VSIX package distributed to users.
    - Leakage of sensitive environment variables or secrets used during the build process.
    - The risk extends to affecting all downstream users of the extension if a compromised build artifact is published.

  - **Vulnerability Rank:** High

  - **Currently Implemented Mitigations:**
    - The script is obtained over HTTPS, which offers a basic level of transport security.
    - Versioned GitHub Actions (e.g., `actions/checkout@v4`) are used elsewhere in the workflow to promote build stability.

  - **Missing Mitigations:**
    - No validation of the downloaded script’s integrity (such as a cryptographic hash or digital signature check) is performed before execution.
    - The workflow does not pin the remote script’s content to a known, trusted version via a checksum or signature check.
    - Additional network‑level protections (or using a locally maintained copy) are absent.

  - **Preconditions:**
    - An attacker must either compromise the remote server hosting the installer script or perform a successful MITM attack against the CI environment’s HTTPS request.
    - The CI infrastructure must execute the downloaded script without any integrity checks.

  - **Source Code Analysis:**
    - In the `.github/workflows/main.yml` (and similarly in `test.yml`), the “Install wasm‑pack” step executes:
      ```yaml
      - name: Install wasm-pack
        run: curl https://rustwasm.github.io/wasm-pack/installer/init.sh -sSf | sh
      ```
    - There is no follow‑up step to verify the downloaded content (for example, by comparing its hash against a trusted value).
    - This pattern trusts data delivered over HTTPS without further verification, leaving the CI process open to remote modifications.

  - **Security Test Case:**
    1. In a controlled test environment (using a proxy or simulated MITM), set up a test substitute for the URL so that it serves a modified version of the installer script. For example, the modified script can write a distinct “compromised” marker file in the CI workspace.
    2. Modify the CI workflow temporarily to point to your controlled URL (or intercept the HTTPS call) so that when the workflow runs, it downloads the tampered script.
    3. Trigger the CI workflow, for example by pushing a minor commit.
    4. Monitor the build logs and check for the presence of the “compromised” marker (or any benign indicative action executed by the script).
    5. If the CI runner executes the modified script without verifying its integrity, the vulnerability is confirmed.