### Vulnerability List

#### 1. Insecure Storage of License Key Activation File

- **Vulnerability Name:** Insecure Storage of License Key Activation File
- **Description:**
    1. User activates the Intelephense extension by entering a license key through the "Enter licence key" command.
    2. The extension sends the license key to `intelephense.com/activate` via an HTTPS POST request for validation.
    3. Upon successful validation (HTTP status 200), the server response (`responseBody`) is written to a file.
    4. The file is stored in the user's global storage path for VS Code, with a predictable filename: `intelephense_licence_key_<licenceKey>`.
    5. An attacker who gains read access to the user's file system can locate and read this file to potentially extract and reuse the license key.
- **Impact:**
    - License key theft: Attackers can steal valid license keys.
    - Unauthorised use of premium features: Stolen license keys can be used to activate premium features of Intelephense without purchasing a license, leading to revenue loss for the developers.
- **Vulnerability Rank:** High
- **Currently Implemented Mitigations:**
    - HTTPS is used for communication with `intelephense.com/activate`, protecting the license key during transmission.
    - The license key is stored in the VS Code global storage path, which is generally user-specific and not publicly accessible by default.
- **Missing Mitigations:**
    - Secure storage mechanisms: Instead of directly writing the response to a file, use more secure OS-level storage options if available, such as the operating system's credential storage or keychain.
    - Encryption: Encrypt the content of the license key file before writing it to storage.
    - Filename obfuscation: Make the filename less predictable to prevent easy discovery. For example, use a hash of the license key or a randomly generated string as part of the filename.
    - Access control: Implement stricter file system permissions to restrict read access to the license key file to only the Intelephense extension process.
- **Preconditions:**
    - The user must have activated a license key for the Intelephense extension.
    - An attacker must gain read access to the user's file system where VS Code stores global extension data. This could be achieved through various methods, including malware, phishing, or exploiting other vulnerabilities in the user's system.
- **Source Code Analysis:**
    ```typescript
    // File: /code/src/extension.ts
    function activateKey(context: ExtensionContext, licenceKey: string): Promise<void> {
        // ...
        return new Promise((resolve, reject) => {
            let responseBody: string = '';
            let req = https.request(options, res => {
                res.on('data', chunk => {
                    responseBody += chunk.toString();
                });
                res.on('end', () => {
                    if (res.statusCode === 200) {
                        let filepath = path.join(context.globalStoragePath, 'intelephense_licence_key_' + licenceKey); // Vulnerable filename construction
                        fs.writeFile(filepath, responseBody).then(resolve, reject); // Insecure file write
                    } else {
                        reject(new Error('Failed to activate key'));
                    }
                });
                res.on('error', reject);
            });
            req.write(postData);
            req.on('error', reject);
            req.end();
        });
    }
    ```
    - The `activateKey` function in `src/extension.ts` constructs the file path using `path.join(context.globalStoragePath, 'intelephense_licence_key_' + licenceKey)`. This creates a predictable filename based on the license key.
    - `fs.writeFile(filepath, responseBody)` then writes the server's response directly to this file without any encryption or access control measures.
- **Security Test Case:**
    1. Install the Intelephense extension in VS Code.
    2. Enter and activate a valid Intelephense license key.
    3. Determine the global storage path for VS Code extensions on your operating system. This path varies depending on the OS and VS Code version. For example, on Linux, it might be under `~/.config/Code/User/globalStorage` or `~/.vscode/extensions`.
    4. Navigate to the Intelephense extension's directory within the global storage path. The directory name will be similar to `bmewburn.intelephense-<version>`.
    5. Look for a file named `intelephense_licence_key_<your_licence_key>`.
    6. Open the file and examine its contents. If the file contains easily extractable license key information or validation tokens that can be reused, the vulnerability is confirmed.