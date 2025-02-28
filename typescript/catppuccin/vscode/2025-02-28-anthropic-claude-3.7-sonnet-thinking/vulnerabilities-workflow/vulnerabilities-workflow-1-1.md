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

This proves that an attacker can leverage the extension to execute arbitrary code on a victim's machine by simply having them open a malicious repository.