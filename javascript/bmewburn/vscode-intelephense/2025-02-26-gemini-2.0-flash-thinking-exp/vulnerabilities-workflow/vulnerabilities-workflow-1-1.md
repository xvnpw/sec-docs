- vulnerability name: Potential Remote Code Execution via License Key Activation
- description: |
  1. The Intelephense extension sends a POST request to `https://intelephense.com/activate` during license key activation.
  2. The response from the server is directly written to a file in the user's global storage path without sanitization or validation.
  3. If the `intelephense.com` server is compromised, a threat actor could manipulate the server to return malicious content in the response.
  4. This malicious content, if crafted as executable code, could be written to the user's file system.
  5. If the extension or another process executes this file, it could lead to remote code execution on the user's machine.
- impact: Remote Code Execution. A successful attack could allow a threat actor to execute arbitrary code on the machine of a user who activates a license key, potentially leading to full system compromise, data theft, or further malicious activities.
- vulnerability rank: critical
- currently implemented mitigations: None. The code directly writes the server response to a file without any security measures.
- missing mitigations:
  - Input validation and sanitization of the response received from `intelephense.com/activate` before writing it to a file.
  - Ensuring that the file written with the server response is never executed as code by the extension or any other process.
  - Implementing integrity checks for the server's response to ensure it originates from a trusted source and hasn't been tampered with.
- preconditions:
  - The user must initiate the license key activation process within the Intelephense extension.
  - The `intelephense.com` domain or the server hosting the activation endpoint must be compromised by a threat actor.
- source code analysis: |
  - File: `/code/src/extension.ts`
  - Function: `activateKey`

  ```typescript
  function activateKey(context: ExtensionContext, licenceKey: string): Promise<void> {
      // ...
      return new Promise((resolve, reject) => {
          let responseBody: string = '';
          let req = https.request(options, res => {
              res.on('data', chunk => {
                  responseBody += chunk.toString(); // Step 1: Accumulate response body
              });
              res.on('end', () => {
                  if (res.statusCode === 200) {
                      let filepath = path.join(context.globalStoragePath, 'intelephense_licence_key_' + licenceKey);
                      fs.writeFile(filepath, responseBody).then(resolve, reject); // Step 2: Write response body to file
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

  The code in `activateKey` function directly takes the `responseBody` received from the `intelephense.com/activate` endpoint and writes it to a file using `fs.writeFile`. There is no validation, sanitization, or security context consideration of the `responseBody` before writing it to the file system. This creates a vulnerability if the server is compromised and serves malicious content.

- security test case: |
  1. **Setup Mock Server:** Configure a local mock server to listen on `https://intelephense.com/activate` (requires DNS spoofing or similar to redirect `intelephense.com` to localhost, or modifying the extension code to point to localhost for testing). This mock server should respond to POST requests to `/activate` with a crafted JSON payload containing malicious Javascript or shell commands within a string value (e.g., `{"licence": "<script>console.log('pwned')</script>"}`).
  2. **Modify Extension (for testing purposes):** For testing, temporarily modify the `activateKey` function in `/code/src/extension.ts` to point the `hostname` in `options` to `localhost` or your mock server's address instead of `intelephense.com`. In a real attack, this step is not needed as the attacker would compromise the actual `intelephense.com` server.
  3. **Run Extension in VS Code:** Launch VS Code with the Intelephense extension activated.
  4. **Trigger License Activation:** Execute the command `Intelephense: Enter licence key` from the VS Code command palette.
  5. **Enter License Key:** Input any arbitrary license key value in the input box and press Enter.
  6. **Observe File System:** Check the global storage path for the Intelephense extension (`context.globalStoragePath`). A file named `intelephense_licence_key_<your_license_key>` should have been created.
  7. **Inspect File Content:** Open the created file and verify if the malicious content (e.g., `<script>console.log('pwned')</script>`) from your mock server's response is present in the file.
  8. **Attempt Code Execution (Advanced):** Further investigate if this file is subsequently parsed or executed by the extension or any other process. If the malicious content is crafted to be executable in a context that the extension uses (e.g., if the extension attempts to load or interpret this file as Javascript or executes shell commands based on its content), it would confirm Remote Code Execution. For a simpler proof of concept, successful injection of malicious content into the file system is sufficient to demonstrate a high-risk vulnerability.