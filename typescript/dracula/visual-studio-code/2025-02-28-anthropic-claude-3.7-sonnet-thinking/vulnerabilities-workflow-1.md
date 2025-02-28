# Vulnerabilities in Dracula for Visual Studio Code

After a thorough analysis of the Dracula for Visual Studio Code theme, I found one vulnerability that could potentially lead to remote code execution. The extension primarily consists of static configuration files, build scripts, and documentation, but does contain one security issue related to YAML processing during the build process.

## Unsafe YAML Deserialization Leading to Remote Code Execution (RCE)

- **Description:**  
  An attacker who supplies a malicious repository can modify the theme's YAML file (located at `/code/src/dracula.yml`) to include dangerous YAML tags. During the build process, the extension's JavaScript code reads and parses this file using the [js-yaml](https://github.com/nodeca/js-yaml) module with an extended schema (see the custom type for `!alpha` in `/code/scripts/generate.js`). If the attacker injects an unsafe payload (for example, using the `!!js/function` tag), the YAML parser may instantiate a function that—if subsequently invoked or if its constructor code is executed during deserialization—can run arbitrary JavaScript code. In a typical attack scenario, a victim clones the repository (as explained in the INSTALL instructions) and later runs the build command (`npm run build`). Because the build process calls `load()` on the manipulated YAML file without forcing a safe schema, the injected payload can trigger code execution in the victim's environment.

- **Impact:**  
  Exploiting this vulnerability can lead to arbitrary code execution in the build (or later runtime) environment. This means an attacker could execute system commands (e.g., spawn processes, read or modify files, or otherwise compromise the victim's machine) when the victim performs standard operations on the extension's source code. Essentially, a compromised theme repository could allow full system compromise of the user's development environment.

- **Vulnerability Rank:** Critical

- **Currently Implemented Mitigations:**  
  There are no explicit mitigations against unsafe YAML deserialization in the current codebase. The project uses `load()` from js-yaml with an extended schema (via `DEFAULT_SCHEMA.extend([withAlphaType])`) in `/code/scripts/generate.js` without limiting dangerous YAML tags.

- **Missing Mitigations:**  
  - Use a strictly safe YAML parser (for example, by replacing `load()` with `safeLoad()` or by explicitly restricting the allowed tags in the schema).  
  - Sanitize or validate all fields within `/code/src/dracula.yml` before processing, ensuring that only expected types and values are accepted.  
  - Lock the js-yaml version to one that enforces safe defaults and avoid enabling constructors that can execute code (such as `!!js/function`).

- **Preconditions:**  
  - The victim must clone or otherwise run the build process (e.g., using `npm run build`) from a repository whose contents have been modified by an attacker.  
  - The malicious repository must include a manipulated `/code/src/dracula.yml` file that contains unsafe YAML tags (for example, `!!js/function`) that the js-yaml parser would process.

- **Source Code Analysis:**  
  - In **`/code/scripts/generate.js`**:  
    - The code reads the file `/code/src/dracula.yml` as a UTF-8 string using `readFile()`.  
    - It then defines a custom YAML type `!alpha` to process sequences (concatenating a hexadecimal color string with an alpha value).  
    - The parser is then configured with a schema built by extending `DEFAULT_SCHEMA` with this custom type.  
    - Finally, the call to `load(yamlFile, { schema })` is used to convert the YAML data into a JavaScript object without explicitly preventing dangerous YAML types (such as `!!js/function` if they are allowed by the version of js-yaml in use).  
    - As a result, if an attacker includes additional nodes using unsafe tags, those nodes will be deserialized and, if their constructors are invoked during parsing, may trigger code execution.

- **Security Test Case:**  
  1. **Prepare a Controlled Test Environment:**  
     - Clone the repository in an isolated environment where you can safely monitor system changes.
  2. **Craft a Malicious YAML Payload:**  
     - Replace the contents of `/code/src/dracula.yml` with the following malicious payload:
       ```yaml
       !!js/function >
         function() {
           // This simulated payload writes to a file as a proof-of-concept.
           require('fs').writeFileSync('/tmp/exploited.txt', 'exploited');
         }
       colors:
         exampleKey: !alpha [ "#FFFFFF", "80" ]
       tokenColors: []
       ```
     - *(Note: Adjust the payload as needed for your testing environment. The goal is to have an executable function injected via YAML.)*
  3. **Run the Build Process:**  
     - Execute `npm run build` so that `/code/scripts/generate.js` is run.
  4. **Verify Code Execution:**  
     - Check for the creation of the file `/tmp/exploited.txt` (or another observable side effect as defined in your payload).  
     - If the file is present (or the payload's side effect is observable), then the arbitrary code execution has been successfully triggered.
  5. **Conclude the Test:**  
     - Document the outcome and ensure that the malicious payload execution constitutes a successful demonstration of the vulnerability.