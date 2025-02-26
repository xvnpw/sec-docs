### Vulnerability List

- Vulnerability Name: Theme Customization Injection
- Description:
    1. An attacker crafts a malicious VSCode settings JSON file.
    2. The attacker tricks a user into importing or applying this malicious settings JSON, for example, through settings synchronization features of VSCode or by sharing the settings file.
    3. The Catppuccin VSCode extension's `utils.updateThemes()` function is triggered when the configuration changes, specifically when `catppuccin.colorOverrides` or `catppuccin.customUIColors` settings are modified.
    4. The `getConfiguration()` function in `utils.ts` reads these settings.
    5. In `compileTheme()` function in `theme/index.ts`, the `colorOverrides` are directly merged into the theme's color palette without sufficient sanitization.
    6. In `uiCustomizations()` in `theme/ui/index.ts`, the `customNamedColors()` function in `theme/ui/customNames.ts` processes `customUIColors`. While it validates color names to be from the Catppuccin palette or "accent", it directly uses provided hex color values without further validation if the input is already in hex format, checked by `hexColorRegex.test(v)`.
    7. Maliciously crafted hex color values within `catppuccin.customUIColors` can therefore bypass the color name validation and be directly injected into the generated theme JSON files.
    8. When VSCode loads and applies the theme, the injected malicious content could lead to unexpected behavior, such as UI corruption or potentially other unforeseen issues depending on how VSCode processes theme files.
- Impact:
    - The most likely impact is UI corruption, where the VSCode theme is rendered incorrectly, potentially hindering usability.
    - In a less likely, but more severe scenario, if VSCode's theme processing has vulnerabilities to injection, it could theoretically lead to other issues, although a full sandbox escape from theme files is highly improbable.
- Vulnerability Rank: High
- Currently implemented mitigations:
    - Not known from the provided project files for runtime sanitization.
    - JSON schema validation is defined for `customUIColors` in `schemas/customUIColors.schema.json`. This schema includes `format: "color-hex"` for validating hex color codes, which is referenced in `src/hooks/updateSchemas.ts` and `src/hooks/updatePackageJson.ts`. However, this schema validation is likely only used by VSCode for settings validation and does not prevent the extension from processing and injecting potentially malicious hex color strings into the theme files at runtime.
- Missing mitigations:
    - Input sanitization for `catppuccin.colorOverrides` and `catppuccin.customUIColors` settings at runtime. Any user-provided values, especially hex color codes in `customUIColors`, should be carefully validated and sanitized before being used to generate theme files. The JSON schema provides a level of validation within VSCode settings UI, but it is not a sufficient security mitigation at runtime.
    - Validation of color values and other injected content at runtime to ensure they conform to expected formats and do not contain any malicious or unexpected characters or commands. For hex colors, ensure they are valid hex codes and do not contain any control characters or escape sequences that could be misinterpreted by JSON parser or VSCode theme engine.
    - Consider using a safer method for applying customizations that avoids direct injection of raw user inputs into theme files. For example, using a controlled templating engine or a more robust configuration merging mechanism that properly encodes or escapes user-provided values.
- Preconditions:
    - A user must import or manually apply a malicious VSCode settings JSON configuration file that contains specially crafted `catppuccin.colorOverrides` or `catppuccin.customUIColors` settings.
    - The `utils.updateThemes()` function and related theme generation logic in the Catppuccin VSCode extension must be vulnerable to injection due to insufficient input sanitization at runtime, specifically in handling hex color values in `customUIColors`.
- Source code analysis:
    - In `/code/packages/catppuccin-vsc/src/utils.ts`, the `updateThemes()` function regenerates theme files based on current configuration. It calls `compileTheme()` from `/code/packages/catppuccin-vsc/src/theme/index.ts`.
    - In `/code/packages/catppuccin-vsc/src/theme/index.ts`, `compileTheme()` merges `colorOverrides` directly into the palette:
        ```typescript
        const palette: CatppuccinPalette = {
            ...ctpPalette,
            ...options.colorOverrides?.all,
            ...options.colorOverrides?.[flavor],
        };
        ```
    - In `/code/packages/catppuccin-vsc/src/theme/ui/customNames.ts`, the `customNamedColors()` function processes `customUIColors`. It uses `parseCustomUiColor()` to validate color names, but if the value is already a hex color (checked by `hexColorRegex`), it's used directly:
        ```typescript
        const customUIColors = {
            ...options.customUIColors.all,
            ...options.customUIColors[flavor],
        };

        for (const [k, v] of Object.entries(customUIColors)) {
            // don't change custom hex colors
            if (hexColorRegex.test(v)) continue;

            const [parsedColor, opacityValue] = parseCustomUiColor(k, v);

            // ... (color name validation logic) ...

            customUIColors[k] = opacity(color, opacityValue);
        }
        ```
    - This direct usage of hex color values from user settings in `customUIColors` without sanitization at runtime allows for potential injection. An attacker can inject malicious strings disguised as hex colors that, when processed by VSCode's theme engine, could cause unexpected behavior.

- Security test case:
    1. Create a malicious VSCode settings JSON file named `malicious_catppuccin_settings.json` with the following content. This test case targets `customUIColors` and injects a string that is a valid hex color format to bypass the hex color check, but is actually a malicious string designed to break JSON syntax or cause UI issues:
    ```jsonc
    {
        "workbench.colorTheme": "Catppuccin Mocha",
        "catppuccin.customUIColors": {
            "all": {
                "activityBar.background": "\";Malicious JSON Injection String\""
            }
        }
    }
    ```
    2. Open Visual Studio Code with the Catppuccin theme extension installed and activated.
    3. Open the VSCode settings (File > Preferences > Settings > Settings or Code > Settings > Settings on macOS).
    4. In the Settings editor, click on the "..." icon in the top-right corner and select "Open Settings (JSON)".
    5. Copy the content of `malicious_catppuccin_settings.json` and paste it into your `settings.json` file, merging it with your existing settings.
    6. Save the `settings.json` file. This action should trigger the `workspace.onDidChangeConfiguration` event and cause the Catppuccin extension to regenerate the theme files using the malicious settings.
    7. Observe Visual Studio Code for any signs of UI corruption, errors, or unexpected behavior. Specifically, check the Activity Bar background color and overall theme rendering. Look for console errors as well.
    8. (Optional, if feasible) Inspect the generated theme JSON files (located in the extension's `themes` directory within your VSCode profile) to verify if the malicious string was injected into the theme file as intended. Look for syntax errors or corrupted JSON structure around `activityBar.background` in the generated theme file (e.g., `mocha.json`).