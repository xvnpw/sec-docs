- **Vulnerability Name:** Command Injection via Unquoted Shell Arguments in Diff Workflow  
  **Description:**  
  In the GitHub Actions workflow defined in the file `.github/workflows/diff.yml`, there is a shell‐script step that iterates over JSON files in the `themes` directory using a plain for‑loop. The invocation uses an unquoted variable (`$file`) to build a diff command:  
  ```
  diff=$(for file in themes/*.json
    do
      diff -U 1 base/$file $file
    done)
  ```  
  An external attacker (via an untrusted pull request) could add a file in the `themes` folder with a specially crafted name containing shell metacharacters (for example, a filename with a semicolon or backticks). When the diff job runs, the shell would interpolate the malicious filename without proper quoting, thereby injecting arbitrary commands into the shell command line.  
  **Impact:**  
  An attacker who successfully triggers this flaw may execute arbitrary commands on the GitHub Actions runner. Such a command‐injection vulnerability can compromise the build environment (for example, by exposing secrets or corrupting the build) and could potentially be leveraged to escalate further attacks.  
  **Vulnerability Rank:** Critical  
  **Currently Implemented Mitigations:**  
  - No quoting or input validation is applied to the file name variable in the diff command.  
  **Missing Mitigations:**  
  - The shell command should safely quote the file name variable (for example, using `"$file"` when constructing the command) or use a safer method (such as iterating over a trusted list of filenames or using tools that avoid shell interpolation).  
  **Preconditions:**  
  - The attacker must be able to submit a pull request that adds (or renames) a file in the `themes` directory using a filename that includes shell metacharacters.  
  **Source Code Analysis:**  
  - In `.github/workflows/diff.yml`, the following code is used to compute the diff:
    ```
    diff=$(for file in themes/*.json
      do
        diff -U 1 base/$file $file
      done)
    ```
    Because the variable `$file` is not wrapped in quotes, its contents are directly interpolated into the shell command. For example, if an attacker adds a file named:  
    `malicious.json; rm -rf /`  
    the executed command might become (roughly):  
    ```
    diff -U 1 base/malicious.json; rm -rf / malicious.json; rm -rf /
    ```  
    This demonstrates the injection vector.  
  **Security Test Case:**  
  1. Fork the repository and create a branch.  
  2. In your branch, add a file under the `themes` directory with a name that contains shell metacharacters (e.g., `test.json; echo "vulnerable" > injected.txt`).  
  3. Open a pull request from your branch.  
  4. Trigger the GitHub Actions workflows (the diff job will run automatically on PRs).  
  5. Examine the logs from the Diff workflow step to determine whether the injected command was executed (for example, by checking for evidence that the string “vulnerable” was echoed or that an unexpected file was created on the runner).  
  6. Verify that when the file name is properly quoted, the injected command does not get executed.

- **Vulnerability Name:** Prototype Pollution via Unrestricted Property Iteration in `changeColorToHexAlphas`  
  **Description:**  
  In the theme‐generation module (`src/theme.js`), the helper function `changeColorToHexAlphas` is used to walk through the raw colors configuration and convert color values to proper hexadecimal strings. Its implementation is as follows:
  ```js
  function changeColorToHexAlphas(obj) {
    if (typeof obj === 'object') {
      for (var keys in obj) {
        if (typeof obj[keys] === 'object') {
          changeColorToHexAlphas(obj[keys])
        } else {
          let keyValue = obj[keys]
          if(chroma.valid(keyValue)){
            obj[keys] = chroma(keyValue).hex();
          }
        }
      }
    }
    return obj;
  }
  ```
  The function iterates over every enumerable property of the supplied object using a `for…in` loop but does not check that each property is an object’s own property (i.e. it does not use `hasOwnProperty` or iterate via `Object.keys()`). If an attacker is able to supply a malicious JSON configuration containing inherited properties (for example, by including a key such as `__proto__`), those properties will be processed and set on the object. This may lead to prototype pollution where properties are added to `Object.prototype`, corrupting the behavior of subsequent object operations.  
  **Impact:**  
  Prototype pollution can have wide‐ranging effects. An attacker might manipulate objects used throughout the extension to bypass security checks or alter functionality. In a worst‑case scenario, when combined with other vulnerabilities, prototype pollution can lead to arbitrary code execution or unsanctioned privilege escalation.  
  **Vulnerability Rank:** High  
  **Currently Implemented Mitigations:**  
  - The current implementation does not restrict iteration to an object’s own properties.  
  **Missing Mitigations:**  
  - The code should be updated to iterate only over own properties by using constructs such as `Object.keys(obj).forEach(...)` or by checking with `if (obj.hasOwnProperty(keys))` (or the equivalent safer check: `Object.prototype.hasOwnProperty.call(obj, keys)`) before processing each property.  
  **Preconditions:**  
  - The attacker must be able to supply a specially crafted JSON configuration (or override file) for theme colors that introduces unexpected inherited keys (for example, a key named `__proto__`). Although the theme files are typically part of the extension’s package, if a user override mechanism is later introduced or if the package’s JSON files are replaced (via a supply‐chain attack), then this vulnerability can be triggered.  
  **Source Code Analysis:**  
  - The function `changeColorToHexAlphas` (in `src/theme.js`) recursively processes every property of the input object without filtering inherited properties.  
  - For instance, if the input object is:
    ```js
    let maliciousInput = {
      "__proto__": { "polluted": true },
      "validColor": "#abcdef"
    };
    ```
    then after processing, the prototype of all objects will include a property `polluted` set to `true`.  
  **Security Test Case:**  
  1. In a controlled test environment (or in an isolated test file), construct a malicious object:
     ```js
     let maliciousInput = {
       "__proto__": { "polluted": true },
       "validColor": "#abcdef"
     };
     ```
  2. Call the function `changeColorToHexAlphas(maliciousInput)`.  
  3. After the function returns, check whether the prototype of a plain object has been altered:
     ```js
     if (({}).polluted === true) {
       console.error("Prototype polluted!");
     }
     ```
  4. Confirm that once the code is corrected to only iterate over own properties, the prototype remains unpolluted.  
  5. Validate that any user‑supplied JSON for theme overrides (if ever supported) is sanitized to reject dangerous keys such as `__proto__`.