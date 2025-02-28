# VS Code Pets Vulnerabilities

After careful analysis of the VS Code Pets extension source code, I have identified the following high-risk security vulnerability:

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

This vulnerability has the potential to lead to remote code execution, as an attacker could craft a payload that causes the extension to load and execute malicious code from a location accessible to the VS Code process.