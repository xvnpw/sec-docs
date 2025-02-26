- **Vulnerability Name:** Arbitrary Code Execution via Malicious Configuration and Custom Rule Files

  - **Description:**  
    The markdownlint extension supports loading JavaScript from configuration files (for example, `.markdownlint.cjs` or `.markdownlint-cli2.cjs`) and from custom rule files specified in user or workspace settings. An attacker can craft a repository that includes a malicious configuration file or custom rule file embedding arbitrary JavaScript. When a user opens such a repository in VS Code and marks the workspace as trusted, the extension will load and execute that JavaScript code. In a step‐by-step scenario, an attacker could:  
    1. Publish a repository with a malicious `.markdownlint.cjs` file (or reference a malicious custom rule via `markdownlint.customRules`).  
    2. Rely on users to clone and open this repository in VS Code.  
    3. When the workspace is marked as trusted, the extension loads the configuration/custom rule file, executing the attacker’s code.  
    4. The attack code might leak sensitive information, modify files on disk, or spawn further processes.
  
  - **Impact:**  
    Exploitation leads to arbitrary code execution within the VS Code process. This can result in full compromise of the user’s environment—allowing the attacker to exfiltrate data, install persistent backdoors, or perform further lateral movement within the system.
  
  - **Vulnerability Rank:** Critical
  
  - **Currently Implemented Mitigations:**  
    - The extension is designed to honor VS Code’s Workspace Trust setting. In an untrusted workspace, JavaScript inside configuration or custom rule files is blocked.  
    - The project’s README clearly documents that running JavaScript from custom rules, markdown‑it plugins, or configuration files is a known security risk.
  
  - **Missing Mitigations:**  
    - There is no additional sandboxing, code signing, or integrity verification for configuration/custom rule files beyond relying on workspace trust.  
    - In environments where a user marks a workspace as trusted (or is tricked into doing so), no further checks prevent the execution of malicious JavaScript.
  
  - **Preconditions:**  
    - The user must open a workspace that is marked as “trusted” in VS Code.  
    - The workspace contains a configuration file (e.g. `.markdownlint.cjs` or `.markdownlint-cli2.cjs`) or a custom rule file that includes malicious code.  
    - The attacker must be able to control or influence the workspace contents (for instance, by hosting a repository with malicious files and persuading the user to open it).
  
  - **Source Code Analysis:**  
    - Although the core code that loads the configuration and custom rules is not detailed in the provided files, the README and accompanying documentation explain that the extension automatically executes JavaScript from these files.  
    - The documentation explicitly warns about this behavior under the “Security” section by noting that running JavaScript from custom rules or configuration files is a risk and that VS Code’s Workspace Trust is used to mitigate this risk.  
    - However, in a trusted workspace context the extension does not perform any additional validation or sandboxing. It directly uses Node.js’s mechanisms (e.g. `require` or dynamic imports) to load and execute the files.  
    - This design means that if an untrusted repository is inadvertently marked as trusted (through social engineering or misconfiguration), the arbitrary code included in a malicious configuration file will run with the privileges of the VS Code process.
  
  - **Security Test Case:**  
    1. **Preparation:**  
       - Create a test repository that includes a file named `.markdownlint.cjs` with the following content:
         ```js
         // .markdownlint.cjs
         // Malicious payload — for testing purposes only!
         const fs = require('fs');
         fs.writeFileSync('pwned.txt', 'This workspace has been compromised');
         module.exports = {};
         ```
       - Optionally, add a custom rule file that logs sensitive data or performs another arbitrary action.
    2. **Execution:**  
       - Clone the repository on a system with VS Code and the markdownlint extension installed.  
       - Open the repository in VS Code and **mark the workspace as trusted** when prompted.  
       - Allow the extension to load the configuration/custom rule files.
    3. **Verification:**  
       - Check for the presence of the file `pwned.txt` in the repository’s root.  
       - Review the developer console (Help → Toggle Developer Tools) for any logs that indicate the malicious payload was executed.  
       - Confirm that the attack’s behavior (e.g., file creation, log entries) is observed, proving that code from a configuration file was executed.
    4. **Cleanup:**  
       - Remove any test artifacts and reset the workspace trust settings as needed.