- **Vulnerability Name**: Prototype Pollution via Untrusted “org.todoKeywords” Configuration Input

- **Description**:  
  An attacker who supplies a malicious workspace configuration can inject dangerous property names into the “org.todoKeywords” array. The extension’s utility function (named `getUniq` in *src/utils.ts*) receives the “org.todoKeywords” values (via `getKeywords`) and builds a plain object in order to filter duplicate values. Because it initializes the mapping object with a plain object literal (`{}`) and does not filter out or sanitize dangerous keys (for example, `__proto__` or `constructor`), a value such as `"__proto__"`—when included by an attacker in the workspace configuration—will be set on the mapping object. In certain JavaScript environments (especially older ones or those not hardened against prototype pollution), this unsanitized assignment could pollute `Object.prototype` and thereby modify the behavior of built‐in objects across the extension, possibly leading to arbitrary code execution or other security bypasses.  

- **Impact**:  
  If the extension’s internal objects are polluted with attacker–controlled properties, then later code that depends on default object behavior (or that merges untrusted objects with trusted ones) may behave in unexpected ways. In worst-case scenarios, prototype pollution can be leveraged to achieve remote code execution or to bypass critical security checks. Because the injected configuration comes from the workspace settings file—which may be provided in a malicious repository—a remote attacker can effectively inject such values into the running extension (when the user opens that repository in VS Code), thus compromising the integrity of the extension’s runtime environment.

- **Vulnerability Rank**: Critical

- **Currently Implemented Mitigations**:  
  • The extension currently reads the “org.todoKeywords” configuration directly via the VS Code configuration API (see *src/utils.ts* in the `getKeywords` function).  
  • There is no sanitization or filtering of the array elements obtained from the user’s workspace settings.  

- **Missing Mitigations**:  
  • Input validation and sanitization for configuration values in “org.todoKeywords” are missing.  
  • The code should explicitly filter out dangerous keys (e.g. `"__proto__"`, `"constructor"`, and similar) before using them in internal processing.  
  • When constructing mapping objects (as in `getUniq`), the code should use a “clean” object (for example, by using `Object.create(null)`) so that prototype properties cannot be inadvertently set.

- **Preconditions**:  
  • The attacker must be able to supply a malicious workspace configuration. In practice, this can happen when a user opens a project repository that includes an “.vscode/settings.json” (or similar configuration) file with a deliberately injected value for `"org.todoKeywords"`.  
  • The user must enable the VS Code Org Mode extension (so that the configuration is read and processed).

- **Source Code Analysis**:  
  1. In *src/utils.ts*, the function `getKeywords` uses  
     ```ts
     const settings = vscode.workspace.getConfiguration("org");
     const todoKeywords = settings.get<string[]>("todoKeywords");
     todoKeywords.push(""); // Since 'nothing' can be a TODO
     return todoKeywords;
     ```  
     This returns an array that comes entirely from workspace configuration without validating its contents.  
  2. In the same file, the helper function `getUniq` is defined as follows:  
     ```ts
     export function getUniq(arr: string[]): string[] {
         const map = {};  // plain object literal is used
         const uniq = [];
         arr.forEach(el => {
             if (!map[el]) {
                 uniq.push(el);
             }
             map[el] = true;
         });
         return uniq;
     }
     ```  
     Here, if an element such as `"__proto__"` is present in the array, the assignment `map["__proto__"] = true;` may alter the prototype chain of objects created later (or even the local object itself), depending on the runtime environment.  
  3. In *src/todo-switch.ts*, the function that advances the TODO state invokes:  
     ```ts
     const todoKeywords = getUniq(getKeywords());
     let nextKeywordIdx = todoKeywords.indexOf(todoString);
     … 
     ```  
     This chain of calls means that unsanitized configuration data is used directly in application logic.  
  4. There is no further validation or escaping of the array values before they are used as keys or parts of regular expressions. This omission leaves open the possibility that an attacker–controlled configuration value can result in prototype pollution.

- **Security Test Case**:  
  1. Prepare a malicious workspace settings file (for example, in “.vscode/settings.json”) with the following content:  
     ```json
     {
       "org.todoKeywords": ["__proto__", "TEST"]
     }
     ```  
  2. Open the malicious project in VS Code so that the Org Mode extension loads this configuration.  
  3. In the command palette, execute any Org Mode command that eventually calls the TODO context code (for example, “org.incrementContext” or “org.decrementContext”).  
  4. After the command is executed, inspect (or script a check in the extension’s debug console) whether `Object.prototype` has been polluted (for example, by checking if `({}).polluted === true` or if additional unexpected properties have appeared on built-in objects).  
  5. If the prototype is polluted and subsequent application behavior is altered (or if further testing leads to arbitrary code paths), then the vulnerability is confirmed.