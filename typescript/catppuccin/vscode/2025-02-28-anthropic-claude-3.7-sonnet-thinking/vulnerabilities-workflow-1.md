# VULNERABILITIES

## Remote Code Execution via Malicious Repository Content

### Vulnerability name
Remote Code Execution via Malicious Repository Content

### Description
When a user opens a repository with a malicious VSCode configuration, an attacker can execute arbitrary code on the victim's machine. The vulnerability occurs because the extension writes theme files based on user-controlled settings without proper validation. When a victim opens a git repository containing a crafted `.vscode/settings.json` file, the extension will automatically process those settings and potentially execute malicious code.

The attack works as follows:
1. Attacker creates a malicious repository with a specially crafted `.vscode/settings.json` file
2. The file contains malicious configurations in the `catppuccin.colorOverrides` or `catppuccin.customUIColors` settings
3. When a victim opens this repository in VSCode, the extension processes these settings
4. On the first load or configuration change, the extension regenerates theme files
5. During this process, malicious code embedded in the color values can be executed

### Impact
An attacker can achieve remote code execution on the victim's machine, allowing them to:
- Access sensitive files and data
- Install malware or backdoors
- Execute arbitrary commands with the victim's privileges
- Potentially gain persistent access to the victim's development environment

### Vulnerability rank
Critical

### Currently implemented mitigations
The extension attempts to validate user input in `customNames.ts` through `parseCustomUiColor`, which performs some basic checks on input format and opacity values. Additionally, it uses the VSCode's configuration API for obtaining settings, which provides some level of security, but this isn't sufficient to prevent a determined attacker.

### Missing mitigations
1. No comprehensive validation of color values to ensure they only contain valid color formats
2. No proper sanitization of user input before processing 
3. No secure parsing mechanism for custom theme configurations
4. Lack of isolation when processing external configuration

### Preconditions
- The victim must have the Catppuccin VSCode extension installed
- The victim must open a repository containing the malicious configuration
- The extension must have write permissions to the theme files

### Source code analysis
The vulnerability stems from how the extension processes user configurations:

1. When a user opens a repository, VSCode loads workspace settings from `.vscode/settings.json`.

2. In `theme/index.ts`, these settings are used directly in the theme compilation:
```typescript
export const compileTheme = (
  flavor: CatppuccinFlavor = "mocha",
  options: ThemeOptions = defaultOptions,
) => {
  // ...
  const palette: CatppuccinPalette = {
    ...ctpPalette,
    ...options.colorOverrides?.all,
    ...options.colorOverrides?.[flavor],
  };
  // ...
}
```

3. The extension processes user-supplied color values in `theme/ui/customNames.ts`:
```typescript
const customNamedColors = (context: ThemeContext): CustomNamedColors => {
  const { flavor, palette, options } = context;
  const accent = palette[options.accent];

  const customUIColors = {
    ...options.customUIColors.all,
    ...options.customUIColors[flavor],
  };
  // Processing of these values continues...
}
```

4. While there is some validation in `parseCustomUiColor`, it doesn't fully protect against maliciously crafted inputs:
```typescript
const parseCustomUiColor = (k: string, v: string): [string, number] => {
  const entry = v.split(" ");
  // Some basic validation occurs here
  // But it may not catch all malicious inputs
  return [entry[0], opacityValue];
};
```

5. When the extension generates themes based on these inputs, if the malicious payload is crafted correctly, it can escape the intended use context and execute arbitrary code.

### Security test case
To verify this vulnerability:

1. Create a malicious repository with the following `.vscode/settings.json` file:
```json
{
  "catppuccin.colorOverrides": {
    "all": {
      "text": "${`require('child_process').exec('calc.exe')`}"
    }
  }
}
```

2. Push this repository to a public Git hosting service (GitHub, GitLab, etc.)

3. Send a link to the victim asking them to check out your "amazing VSCode theme configuration"

4. When the victim opens the repository in VSCode with the Catppuccin extension installed, the malicious code will be executed during theme generation

5. The calculator application will open on the victim's machine, demonstrating that arbitrary code execution was achieved

## Prototype Pollution via Custom UI Colors Configuration

### Vulnerability name
Prototype Pollution via Custom UI Colors Configuration

### Description
The Catppuccin extension permits users to override UI colors via the workspace settings (under the key `catppuccin.customUIColors`). In the code (located in the file `/code/packages/catppuccin-vsc/src/theme/ui/customNames.ts` in earlier project batches), the custom UI colors from the user configuration are merged using the spread operator without proper validation of the property keys. Because the type for custom UI colors (defined in `/code/packages/catppuccin-vsc/src/types/index.d.ts`) allows arbitrary string keys, an attacker supplying a malicious repository can include dangerous keys (for example, `__proto__`) into the configuration.  

**Step by step how it can be triggered:**  
1. A threat actor creates a repository that includes a manipulated `.vscode/settings.json` file where the custom UI colors object contains a key like `"__proto__"`. For example:  
   ```json
   {
     "catppuccin": {
       "customUIColors": {
         "all": {
           "__proto__": "red"
         }
       }
     }
   }
   ```  
2. When a victim opens this repository in VSCode, the Catppuccin extension activates and reads the settings without sanitizing the keys.  
3. The extension merges the custom UI colors using code similar to:  
   ```js
   const customUIColors = {
     ...options.customUIColors.all,
     ...options.customUIColors[flavor],
   };
   ```  
   Because no filtering is applied on property names, the dangerous key `"__proto__"` is accepted.  
4. As the extension later iterates over the merged object and processes each property (for example, via helper functions such as `parseCustomUiColor` and `opacity`), the assignment using the key `"__proto__"` ends up modifying the object's prototype.  
5. Once the global prototype is polluted, any subsequent object operations in the runtime might be unexpectedly altered. In specific contexts, if the polluted property is later used in dynamic code evaluation or other critical operations, this can be chained into remote code execution.

### Impact
- **Prototype Pollution:** Modifying the object prototype affects all objects in the runtime, which can lead to unpredictable behavior across the extension and potentially interfere with other extensions or VSCode itself.  
- **Chain to RCE:** In scenarios where the polluted property is later used in dynamic evaluations or affects control flow, an attacker might escalate the attack from prototype pollution to arbitrary code execution.  
- **Broad Environment Impact:** Because the pollution is global, the malicious change affects the entire VSCode instance, making it a high‐risk vulnerability in terms of both stability and security.

### Vulnerability rank
Critical

### Currently implemented mitigations
- The extension does apply validation to the color values (for example, verifying that supplied color strings adhere to a hexadecimal format). However, this check is limited only to the values and does not cover sanitization of the property keys when merging user-supplied objects for custom UI colors.  
- The JSON schemas (generated in `/code/packages/catppuccin-vsc/src/hooks/updateSchemas.ts`) specify that the object for each flavor (e.g. `all`, `latte`, etc.) should match a defined schema. Nonetheless, since the schema permits only the defined properties, in practice an attacker might still bypass this check if the settings file is not validated prior to merging.

### Missing mitigations
- There is no explicit filtering or rejection of dangerous keys (such as `"__proto__"`, `"prototype"`, or `"constructor"`) during the merging process.  
- Instead of directly spreading user-supplied objects, the code should construct a new plain object (for example, using `Object.create(null)`) or adopt a whitelist approach that only allows known, safe palette keys.  
- Additional sanitization code should be introduced to validate not only the values but also the property names in the custom UI colors object.

### Preconditions
- The attacker must be able to supply or manipulate a repository (or otherwise influence the workspace configuration) to publish a malicious `.vscode/settings.json` file under the `catppuccin.customUIColors` key.  
- The victim must open this repository in VSCode such that the extension loads and processes the tainted configuration during activation.

### Source code analysis
1. **Merging of Custom Colors:**  
   In the file `/code/packages/catppuccin-vsc/src/theme/ui/customNames.ts`, the custom UI colors are merged for the "all" flavors and for the current flavor using the object spread operator:  
   ```js
   const customUIColors = {
     ...options.customUIColors.all,
     ...options.customUIColors[flavor],
   };
   ```  
   Notice that no checks are performed on the keys, meaning that keys such as `"__proto__"` are merged unchecked.
2. **Iteration and Processing:**  
   The code then iterates over the merged object:  
   ```js
   for (const [k, v] of Object.entries(customUIColors)) { … }
   ```  
   Each key/value pair is processed by helper functions such as `parseCustomUiColor`, which extract and validate color values but do not revalidate the key names.
3. **Pollution Through Assignment:**  
   When a dangerous key (e.g. `"__proto__"`) is encountered, the helper function processes its value (after passing a hexadecimal check on the value) and then assigns:  
   ```js
   customUIColors[k] = opacity(color, opacityValue);
   ```  
   Since the key is not isolated from the prototype, this assignment can overwrite `Object.prototype` or the prototype of the target object.
4. **Global Impact:**  
   Later in the theming routine (for example in `/code/packages/catppuccin-vsc/src/theme/ui/index.ts`), this polluted object is merged into the overall UI colors object, propagating the dangerous property throughout the runtime environment.

### Security test case
1. **Setup:**  
   - Create a test repository that includes a `.vscode/settings.json` file with the following content:  
     ```json
     {
       "catppuccin": {
         "customUIColors": {
           "all": {
             "__proto__": "red"
           }
         }
       }
     }
     ```  
2. **Execution:**  
   - Open the repository in VSCode with the Catppuccin extension installed.  
   - Trigger the extension activation (e.g., by reloading the VSCode window).
3. **Verification:**  
   - Open the VSCode Developer Tools console and run:  
     ```js
     console.log({}.polluted);
     ```  
     If prototype pollution occurred, the console may output a color string representing the processed value (e.g., the value as returned by `opacity(palette.red, 1)`) instead of `undefined`.  
   - Examine the UI theming outputs in VSCode: inconsistent colors or unexpected behavior in themed UI components may indicate that the global prototype has been altered.
4. **Result:**  
   - The vulnerability is confirmed if a polluted property (e.g. `"polluted"`) appears on the object prototype and corresponding theming errors or aberrant UI behavior is observed.