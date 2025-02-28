# Vulnerabilities List

## Unsafe YAML Deserialization in Config File Processing

- **Description:**  
  The extension reads configuration files (such as `infracost.yml`) from the workspace without explicitly enforcing a safe parsing schema. In particular, within the Workspace's initialization logic the file is read and passed directly to the [js-yaml](https://github.com/nodeca/js-yaml) library's `load` function:
  - The file encoding is determined by calling `getFileEncoding(configFilePath)`.
  - The file is then read using `readFileSync(configFilePath, encoding)` and deserialized with `load(...)`.
  
  If a threat actor supplies a manipulated repository containing a malicious `infracost.yml` file, they can include unsafe YAML constructs (for example, using tags like `!!js/function` to define and inject executable code) that will be deserialized. As a result, when the extension processes the configuration file it could inadvertently execute arbitrary JavaScript code.
  
- **Impact:**  
  An attacker who convinces a user to open a crafted repository can trigger arbitrary code execution (RCE) in the context of the VS Code extension. This could result in the compromise of the victim's local environment, access to sensitive files, or further lateral movement within the user's system.
  
- **Vulnerability Rank:**  
  Critical

- **Currently Implemented Mitigations:**  
  • There is no explicit mitigation present in the source code. The file is parsed by directly calling `load(...)` from js-yaml without specifying a safe schema or using a safe-loading method.

- **Missing Mitigations:**  
  • Use a safe YAML parsing function (for example, switch to `safeLoad` or configure `load` with a safe schema that does not support unsafe tags).  
  • Validate and sanitize the contents of any configuration file (especially files at the workspace's root) before deserialization.

- **Preconditions:**  
  • The victim must open a repository in VS Code that contains a manipulated configuration file (e.g. an `infracost.yml` file) provided by a threat actor.  
  • The version of the js-yaml library in use must allow unsafe types (for instance, if it does not enforce a safe schema by default).

- **Source Code Analysis:**  
  1. In `/code/src/workspace.ts`, inside the `runConfigFile` method, the code determines the file encoding by calling `await getFileEncoding(configFilePath)`.  
  2. The file is then read and deserialized with:
     ```js
     const doc = <ConfigFile>load(readFileSync(configFilePath, encoding as BufferEncoding));
     ```
  3. No safe-loading options or schema restrictions are applied when calling `load`.  
  4. As the config file is expected to be provided at the root of the repository, a threat actor controlling the repository can supply a malicious YAML payload (for example, embedding a `!!js/function` tag) that may execute arbitrary code during deserialization.

- **Security Test Case:**  
  1. **Setup:**  
     - Create a test repository that includes an `infracost.yml` file at its root.  
     - In this file, inject a malicious YAML payload such as:
       ```yaml
       !!js/function >
         function () { require('child_process').exec('calc'); }
       projects:
         - path: dev
           name: development
           skip_autodetect: false
       ```
       *(On Windows, this payload would attempt to launch the Calculator application as a visible proof of code execution.)*
  2. **Execution:**  
     - Open Visual Studio Code and use the Infracost extension by opening the test repository.
     - Observe the extension's startup and the workspace initialization sequence.
  3. **Verification:**  
     - Verify whether the injected payload is executed (e.g. seeing the Calculator app open on Windows or by examining side effects in the extension logs).
     - If the payload is executed, this confirms that the YAML deserialization is unsafe.
  4. **Cleanup:**  
     - Remove the malicious content and re-test to ensure that the extension works normally in a repository with only valid configuration files.