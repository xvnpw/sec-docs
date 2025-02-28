# Vulnerabilities

## 1. Code Injection via Unsanitized Mapping Keys in Export-to-TS Script

- **Description:**
  - The `export-to-ts.js` script reads a JSON mapping file (typically located at `src/template/mapping.json`) and generates a TypeScript module by iterating over its entries.
  - For each mapping entry, the script produces code with a template literal that directly interpolates the mapping key (`name`) into a call to `register`:
    ```js
    console.log(`\t${toCamelCase(name)}: register('${name}', ${decimalToHex(value)}),`);
    ```
  - The helper function `toCamelCase(name)` only handles hyphen-to-camel conversion and does not remove or escape characters such as single quotes or other code delimiters.
  - An attacker who supplies a manipulated `mapping.json` with malicious keys (for example, keys containing quotes and injected JavaScript code) can break out of the intended string context and insert arbitrary code into the generated module.
  - Once this malicious module is incorporated into the VSCode extension (as per the build process), the injected code is executed in the extension's runtime.

- **Impact:**
  - This vulnerability allows an attacker to perform Remote Code Execution (RCE) within the context of the VSCode extension.
  - Arbitrary JavaScript code (or commands) could be executed on the victim's machine, potentially leading to system compromise or exposure of sensitive data.

- **Vulnerability Rank:** Critical

- **Currently Implemented Mitigations:**
  - There is no sanitization or proper escaping of the mapping keys in `export-to-ts.js`.
  - The only transformation applied is via the `toCamelCase()` function, which does not mitigate injection risks.

- **Missing Mitigations:**
  - **Input Validation/Sanitization:** The project should validate and sanitize all keys read from `mapping.json` before using them in code generation.
  - **Proper Escaping:** When outputting the mapping keys inside code (within string literals), a robust escaping mechanism should be employed to neutralize any special characters.
  - **Use of Secure Templating Engine:** Consider leveraging a templating system that automatically escapes injected values to prevent code injection.

- **Preconditions:**
  - The attacker must supply a manipulated repository that includes a tampered `mapping.json` file with specially crafted keys containing injection payloads.
  - The victim must run the repository's build process (which involves executing the `export-to-ts.js` script) so that the malicious mapping is processed and the generated code is later incorporated and executed by the VSCode extension.

- **Source Code Analysis:**
  - **Step 1:** The script begins by reading the file passed with the `-f` flag:
    ```js
    fs.readFile(opts.f, 'utf8', (err, data) => { ... });
    ```
  - **Step 2:** It parses the file using `JSON.parse(data)` to obtain the mapping object.
  - **Step 3:** The script loops over the mapping entries:
    ```js
    Object.entries(mapping).forEach(([name, value]) => {
      console.log(`\t${toCamelCase(name)}: register('${name}', ${decimalToHex(value)}),`);
    });
    ```
    - Here, the variable `name` comes directly from the JSON file.
  - **Step 4:** The helper function `toCamelCase(name)` is used to generate an identifier but it does not provide any escaping for characters like single quotes.
  - **Step 5:** If an attacker sets a mapping key such as:
    ```
    "icon'); require('child_process').exec('malicious_command'); //"
    ```
    the generated output becomes:
    ```js
    icon: register('icon'); require('child_process').exec('malicious_command'); //', 0x3039),
    ```
    - This output effectively closes the intended string literal and injects additional code.
  - **Step 6:** As the generated TypeScript module is later used by the extension, this injected code is executed with the same privileges as the extension, leading to arbitrary code execution.

- **Security Test Case:**
  1. **Set Up a Malicious Mapping File:**
     - Create a file named `mapping.json` with the following content:
       ```json
       {
         "icon'); require('child_process').exec('calc'); //": 12345
       }
       ```
       (On Windows, the command `calc` opens the Calculator. Use an equivalent harmless command in your test environment.)
  2. **Run the Export Script:**
     - Execute the script in a safe testing environment:
       ```bash
       node scripts/export-to-ts.js -f path/to/malicious/mapping.json
       ```
  3. **Inspect the Generated Output:**
     - Verify that the output (written to stdout or redirected to a file) contains the injected payload. Look for a line resembling:
       ```js
       icon: register('icon'); require('child_process').exec('calc'); //', 0x3039),
       ```
  4. **Simulate Integration:**
     - Integrate the generated module into a controlled version of the VSCode extension build process.
  5. **Observe Execution:**
     - Run the extension in a sandboxed environment and verify that the malicious payload executes (e.g., observe that Calculator is launched or another harmless command is triggered).
  6. **Document the Test:**
     - Record the steps and outcomes to confirm that the vulnerability is exploitable as described.