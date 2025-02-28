# Vulnerabilities in Infracost VS Code Extension

## 1. YAML Deserialization Remote Code Execution

- **Vulnerability name**: YAML Deserialization Remote Code Execution
- **Description**: The Infracost VS Code extension is vulnerable to a YAML deserialization attack that could allow remote code execution. When a victim opens a repository containing a malicious `infracost.yml` or `infracost.yml.tmpl` file, the extension reads and parses these files using the `js-yaml` library's `load()` function without any input validation or sanitization. If the extension uses a vulnerable version of `js-yaml` (prior to 3.13.1), this can lead to arbitrary code execution through malicious YAML tags.

  Step by step attack flow:
  1. Attacker creates a malicious repository with an `infracost.yml` file containing dangerous YAML tags like `!!js/function`
  2. Victim clones and opens the repository in VS Code with the Infracost extension installed
  3. The extension automatically reads and parses the config file
  4. The malicious YAML is deserialized, executing the attacker's code

- **Impact**: The vulnerability allows an attacker to execute arbitrary code in the context of the VS Code application, which could lead to:
  - Data exfiltration from the victim's workspace
  - Access to any resources accessible to the VS Code process
  - Potential lateral movement to other repositories or systems
  - Installation of additional malware or backdoors

- **Vulnerability rank**: Critical

- **Currently implemented mitigations**: There are no visible mitigations in the codebase to prevent this attack. The extension directly uses the `load()` function from `js-yaml` without any validation or sanitization of the input.

- **Missing mitigations**:
  - Use `safeLoad()` instead of `load()` to disable potentially dangerous YAML tags
  - Ensure the extension uses a secure version of `js-yaml` (3.13.1 or later)
  - Implement input validation and structure verification before parsing YAML files
  - Consider using a schema to validate the YAML structure before processing

- **Preconditions**:
  - Victim must have the Infracost VS Code extension installed
  - Victim must open a repository containing a malicious YAML configuration file
  - The extension must be using a vulnerable version of `js-yaml`

- **Source code analysis**:
  In `workspace.ts`, the extension reads and parses the configuration file:
  
  ```typescript
  async run(...changedProjectPaths: string[]): Promise<infracostJSON.Project[] | undefined> {
    // ...
    const templateFilePath = path.join(this.root, CONFIG_TEMPLATE_NAME);
    const hasTemplateFilePath = existsSync(templateFilePath);
    let configFilePath = path.join(this.root, CONFIG_FILE_NAME);
    if (hasTemplateFilePath) {
      // ...
    }
    
    const hasConfigFile = existsSync(configFilePath);
    // ...
  }
  
  async runConfigFile(
    changedProjectPaths: string[],
    configFilePath = path.join(this.root, CONFIG_FILE_NAME)
  ): Promise<infracostJSON.Project[]> {
    // ...
    const encoding = await getFileEncoding(configFilePath);
    const doc = <ConfigFile>load(readFileSync(configFilePath, encoding as BufferEncoding));
    // ...
  }
  ```
  
  The vulnerability lies in the direct use of `load()` from `js-yaml` without any validation. When the extension processes either `infracost.yml` or `infracost.yml.tmpl` files from the root of the workspace, it reads the file and passes its contents directly to `load()`. If this is a vulnerable version of `js-yaml`, malicious YAML tags will be processed and executed.

- **Security test case**:
  1. Create a repository with a malicious `infracost.yml` file containing:
     ```yaml
     version: 0.1
     projects:
       - path: .
         evil: !!js/function >
           function f() {
             return require('child_process').execSync('calc.exe').toString();
           }
     ```
  2. Clone the repository and open it in VS Code with the Infracost extension installed
  3. The extension will automatically read and parse the configuration file
  4. If vulnerable, the calculator application will launch, demonstrating code execution
  5. For a more realistic attack, the code could exfiltrate sensitive data or install a backdoor

## 2. Command Injection via Template Configuration Processing

- **Vulnerability name**: Command Injection via Template Configuration Processing
- **Description**: The Infracost VS Code extension is vulnerable to command injection when processing template configuration files. When a victim opens a repository containing a specially crafted `infracost.yml.tmpl` file, the extension will execute the `infracost generate config` command with attacker-controlled input, potentially leading to command injection.

  Step by step attack:
  1. Attacker creates a malicious repository with a specially crafted `infracost.yml.tmpl` file
  2. Victim opens the repository in VS Code with the Infracost extension
  3. The extension executes the CLI command to process the template
  4. If the template contains malicious content that can escape argument handling, commands can be injected

- **Impact**: Successful exploitation would allow an attacker to execute arbitrary commands on the victim's system in the context of the VS Code process, potentially leading to full system compromise.

- **Vulnerability rank**: High

- **Currently implemented mitigations**: The extension uses Node.js's `spawn()` function with an array of arguments which typically prevents shell injection attacks. However, the content of the template file is fully controlled by the attacker and is not validated.

- **Missing mitigations**:
  - Validate the template file content before processing
  - Sanitize all inputs passed to the CLI process
  - Consider running the CLI in a restricted environment

- **Preconditions**:
  - Victim must have the Infracost VS Code extension installed
  - Victim must open a repository with a malicious `infracost.yml.tmpl` file
  - The CLI process must be vulnerable to command injection through template processing

- **Source code analysis**:
  In `workspace.ts`, the extension processes template configuration files:
  
  ```typescript
  async run(...changedProjectPaths: string[]): Promise<infracostJSON.Project[] | undefined> {
    try {
      const templateFilePath = path.join(this.root, CONFIG_TEMPLATE_NAME);
      const hasTemplateFilePath = existsSync(templateFilePath);
      let configFilePath = path.join(this.root, CONFIG_FILE_NAME);
      if (hasTemplateFilePath) {
        configFilePath = path.join(tmpdir(), CONFIG_FILE_NAME);
        const out = await this.cli.exec([
          'generate',
          'config',
          '--template-path',
          templateFilePath,
          '--repo-path',
          this.root,
          '--out-file',
          configFilePath,
        ]);
        
        if (out.stderr !== '') {
          await context.set(ERROR, `${out.stderr}.`);
          return undefined;
        }
      }
      // ...
    }
    // ...
  }
  ```
  
  The extension directly passes the `templateFilePath` to the CLI without validating its content. While `spawn()` with array arguments prevents shell command injection, the template file itself could contain malicious content that the CLI might process in an unsafe manner. If the `generate config` command in the CLI doesn't properly handle template content, this could lead to command injection.

- **Security test case**:
  1. Create a repository with a malicious `infracost.yml.tmpl` file containing content designed to escape argument handling in the CLI
  2. Clone the repository and open it in VS Code with the Infracost extension
  3. The extension will automatically process the template file
  4. If vulnerable, the payload in the template will cause command execution
  5. Verify by having the command create a file or make a network connection as proof of execution