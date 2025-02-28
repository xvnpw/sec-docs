# VS Code Pets Vulnerabilities

After careful analysis of the VS Code Pets extension source code, the following security vulnerabilities have been identified:

## 1. Path Traversal via Malicious JSON Import/Export

### Description
The VS Code Pets extension allows users to import pet configurations from JSON files. When importing, the extension doesn't properly validate the pet types and colors before constructing file paths, which can lead to directory traversal attacks. An attacker can craft a malicious JSON file with specially constructed pet type or color values containing path traversal sequences (e.g., `../`).

When a pet is created, its image source is constructed using:
```typescript
const root = basePetUri + '/' + petType + '/' + petColor;
this.el.src = `${this.petRoot}_${face}_8fps.gif`;
```

### Impact
This vulnerability allows an attacker to:
- Load arbitrary files from the user's filesystem
- Potentially execute malicious code if they can trick the extension into loading JavaScript files
- Access sensitive information outside the extension's intended directory scope

### Vulnerability Rank
High

### Currently Implemented Mitigations
The code does attempt to validate pet colors against available colors for a specific pet type:
```typescript
if (!availableColors(petType).includes(petColor)) {
    throw new InvalidPetException('Invalid color for pet type');
}
```

However, this validation is insufficient because:
1. It doesn't sanitize the input values for path traversal characters
2. The validation can be bypassed when importing pets from JSON

### Missing Mitigations
1. Input sanitization for petType and petColor to remove path traversal sequences
2. Use of path normalization functions before constructing file paths
3. Strict validation against an allowed list of values, rejecting any values that don't match exactly
4. Implementation of a proper Content Security Policy that restricts where resources can be loaded from

### Preconditions
1. An attacker crafts a malicious JSON pet configuration file
2. The victim is convinced to import this file into their VS Code Pets extension
3. The victim has the VS Code Pets extension installed and activated

### Source Code Analysis
When a user imports pets from a JSON file in `extension.ts`:

```typescript
const fileContents = await vscode.workspace.fs.readFile(fileUri[0]);
const petsToLoad = JSON.parse(String.fromCharCode.apply(null, Array.from(fileContents)));

for (let i = 0; i < petsToLoad.length; i++) {
    const pet = petsToLoad[i];
    const petSpec = new PetSpecification(
        normalizeColor(pet.color, pet.type),
        pet.type,
        pet.size,
        pet.name,
    );
    collection.push(petSpec);
    if (panel !== undefined) {
        panel.spawnPet(petSpec);
    }
}
```

This creates a `PetSpecification` object which is then passed to `spawnPet()`. Inside the panel implementation, a pet element is created:

```typescript
function addPetToPanel(...) {
    // ...
    const root = basePetUri + '/' + petType + '/' + petColor;
    // ...
    var newPet = createPet(
        petType,
        petSpriteElement,
        collisionElement,
        speechBubbleElement,
        petSize,
        left,
        bottom,
        root,
        floor,
        name,
    );
    // ...
}
```

Later, when animating the pet, the `setAnimation()` method is called:

```typescript
setAnimation(face: string) {
    if (this.el.src.endsWith(`_${face}_8fps.gif`)) {
        return;
    }
    this.el.src = `${this.petRoot}_${face}_8fps.gif`;
}
```

This sets the image source directly using the `petRoot` which contains the unsanitized `petType` and `petColor` values. If these values contain path traversal sequences, they can be used to load files from outside the intended directory.

### Security Test Case

1. Create a malicious JSON file with the following content:
```json
[
  {
    "color": "../../../../../../etc/passwd",
    "type": "cat",
    "size": "nano",
    "name": "MaliciousPet"
  }
]
```

2. Save this file as `malicious-pets.json` in a repository

3. Push this repository to GitHub

4. Have the victim:
   - Clone the repository
   - Open it in VS Code
   - Run the VS Code Pets extension
   - Execute the "Import Pet List" command
   - Select the malicious JSON file

5. Observe that the extension attempts to load a file from outside its intended directory, potentially exposing sensitive files

6. For a more advanced attack, create a JSON with a payload that points to a specially crafted GIF with an embedded exploit:
```json
[
  {
    "color": "../../../../../../tmp/malicious",
    "type": "cat",
    "size": "nano",
    "name": "MaliciousPet"
  }
]
```

7. Place a malicious file at the targeted location that could be executed when loaded by the webview

## 2. Webview Inline Script Injection via Unsanitized Configuration Values

### Description
The extension builds its webview HTML dynamically in the function that generates the inline HTML for the pet panel (via `_getHtmlForWebview` in the extension's TypeScript file). In this process, several configuration-derived values are injected directly into an inline JavaScript call without proper escaping or sanitization. For example, the HTML is generated as follows:

```
<script nonce="${nonce}" src="${scriptUri}"></script>
<script nonce="${nonce}">
     petApp.petPanelApp("${basePetUri}", "${this.theme()}", ${this.themeKind()}, "${this.petColor()}", 
     "${this.petSize()}", "${this.petType()}", ${this.throwBallWithMouse()}, ${this.disableEffects()});
</script>
```

The values (such as those returned by `this.theme()`, `this.petColor()`, `this.petSize()`, and `this.petType()`) come directly from the user's configuration settings (read via `vscode.workspace.getConfiguration('vscode-pets').get(...)`). A threat actor who supplies a malicious repository may provide a ".vscode/settings.json" that sets one or more of these values to strings containing embedded double quotes and JavaScript code (for example, using a payload like `"cat\",alert('Injected'),\""`). This results in an inline script that inadvertently executes the injected code in the webview's context.

### Impact
An attacker controlling the repository configuration can force the webview to execute arbitrary JavaScript code. This Remote Code Execution (RCE) in the webview context may allow the attacker to read or modify sensitive workspace data, interact with the VS Code API with elevated privileges, and fundamentally compromise the developer's session.

### Vulnerability Rank
Critical

### Currently Implemented Mitigations
- The webview uses a strict Content Security Policy (CSP) that includes a nonce to restrict external script loading.  
- However, the CSP does not mitigate injection within dynamically generated inline scripts when unsanitized configuration values are interpolated.

### Missing Mitigations
- There is no sanitization or escaping applied to the configuration values (e.g., "theme", "petColor", "petSize", "petType") before they are concatenated into the inline JavaScript.  
- A mitigation would be to JSON‑serialize these values using `JSON.stringify(...)` so that any embedded quotes or special characters are properly escaped.  
- Alternatively, refactoring the code to avoid constructing inline scripts from dynamic data would prevent the issue entirely.

### Preconditions
- The victim must open a workspace or repository that contains a malicious ".vscode/settings.json" (or similar configuration file) where keys under "vscode-pets" (such as "petType", "petColor", "petSize", or "theme") have been maliciously modified.  
- When the extension reads these configuration values (typically during startup or when the "Start pet coding session" command is executed), the unsafe values are injected into the webview's HTML.

### Source Code Analysis
- In the extension's source code (for example, in `/code/src/extension/extension.ts`), the function `_getHtmlForWebview(webview)` constructs the HTML for the pet panel.
- It creates an inline script as shown:
  ```
  <script nonce="${nonce}" src="${scriptUri}"></script>
  <script nonce="${nonce}">
      petApp.petPanelApp("${basePetUri}", "${this.theme()}", ${this.themeKind()}, "${this.petColor()}", "${this.petSize()}", "${this.petType()}", ${this.throwBallWithMouse()}, ${this.disableEffects()});
  </script>
  ```
- The values such as `this.theme()`, `this.petColor()`, etc., are obtained from user configuration without performing any validation or escaping.
- Because these values are embedded inside JavaScript string literals in inline code, a payload supplied by a malicious ".vscode/settings.json" can break out of the string context and execute arbitrary code in the webview.

### Security Test Case
1. Create a test workspace and within it add a file `.vscode/settings.json` with the following content:
   ```json
   {
     "vscode-pets.petType": "cat\",alert('Injected'),\""
   }
   ```
2. Open this test workspace in VS Code so that the extension reads the malicious configuration settings.
3. Execute the "Start pet coding session" command (i.e. run the command registered as `vscode-pets.start`).
4. Observe that when the webview is displayed, the inline script executes the injected code (for example, an alert box appears).
5. The execution of the alert confirms that the unsanitized configuration value led to arbitrary code execution, validating the vulnerability.