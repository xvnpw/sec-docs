### Vulnerability List:

#### 1. Insecure Binary Download without Checksum Validation

- **Description:**
    1. The `download.sh` script is used to download the Infracost CLI binary during the extension packaging process.
    2. The script fetches both the binary and its SHA256 checksum from `https://infracost.io/downloads/latest`.
    3. The script attempts to validate the downloaded binary using the SHA256 checksum.
    4. However, if the SHA256 checksum file is not found at the specified URL (returns HTTP 404), the script proceeds without performing checksum validation.
    5. An attacker who compromises `infracost.io` could remove the SHA256 checksum files for specific releases.
    6. When the `download.sh` script is executed in such a scenario, it will download the binary and skip checksum validation, potentially downloading a malicious binary if the attacker also replaces the binary on the server.
    7. This malicious binary would then be packaged within the VSCode extension and distributed to users.

- **Impact:**
    - **Critical**
    - If an attacker successfully replaces the Infracost CLI binary hosted on `infracost.io` and removes the corresponding SHA256 checksum file, users downloading or updating the VSCode extension could unknowingly install a compromised version of the Infracost CLI.
    - This compromised CLI binary could execute arbitrary code on the user's machine with the privileges of the VSCode extension.
    - This could lead to sensitive data exfiltration (e.g., Terraform configurations, cloud credentials if accessible), installation of malware, or further compromise of the user's system.
    - As the extension is widely used by developers, the impact could be widespread.

- **Vulnerability Rank:** critical

- **Currently Implemented Mitigations:**
    - **Partial Mitigation:** The `download.sh` script attempts to perform SHA256 checksum validation under normal circumstances.
    - The script includes the logic to download and validate the SHA256 checksum of the Infracost CLI binary.
    - This is done by:
        - Downloading the `.sha256` file.
        - Using `shasum -sc` to compare the checksum.
        - Exiting if the checksum validation fails.

    - **Location:** `scripts/download.sh`

- **Missing Mitigations:**
    - **Critical Missing Mitigation:** The script lacks a fallback mechanism or error handling when the SHA256 checksum file is not found (HTTP 404).
    - Instead of skipping checksum validation, the script should fail and prevent the download process if the checksum file is missing.
    - This would ensure that binary validation is always enforced, even if the checksum file is temporarily or permanently unavailable.
    - **Missing Mitigation:** Implement signature verification of the binary.
    - Relying solely on SHA256 checksums, while helpful for detecting corruption, does not guarantee the authenticity and integrity of the binary against a sophisticated attacker who might compromise the distribution server.
    - Digitally signing the Infracost CLI binary would provide a stronger layer of security by allowing verification of the publisher's identity and ensuring that the binary has not been tampered with since it was signed.

- **Preconditions:**
    - **Attacker Compromise:** The attacker must have compromised the `infracost.io` infrastructure sufficiently to:
        - Replace the legitimate Infracost CLI binary with a malicious one.
        - Remove the corresponding SHA256 checksum file for the replaced binary.
    - **Extension Packaging or Re-download:** The VSCode extension packaging process must execute the `download.sh` script after the attacker has made these changes, or a user must re-download the extension after these changes.

- **Source Code Analysis:**
    1. **File:** `/code/scripts/download.sh`
    2. **Vulnerable Code Block:**
    ```sh
    code=$(curl -s -L -o /dev/null -w "%{http_code}" "$url/$tar.sha256")
    if [ "$code" = "404" ]; then
      echo "Skipping checksum validation as the sha for the release could not be found, no action needed."
    else
      echo "Validating checksum for infracost-$bin_target..."
      curl -sL "$url/$tar.sha256" -o "/tmp/$tar.sha256"

      if ! check_sha "$tar.sha256"; then
        exit 1
      fi

      rm "/tmp/$tar.sha256"
    fi
    ```
    3. **Explanation:**
        - The script uses `curl` to check the HTTP status code of the SHA256 checksum file URL.
        - If the status code is "404" (Not Found), the script interprets this as the SHA256 file not being available.
        - In this case, it prints a message "Skipping checksum validation..." and proceeds without validating the binary.
        - This logic is flawed because a missing checksum file should be treated as a security risk, not a benign condition.
        - An attacker can exploit this by removing the SHA256 file after replacing the binary on the server.
        - The `check_sha` function itself is correctly implemented for checksum validation when the SHA256 file is available.
        - The vulnerability lies in the conditional logic that allows skipping validation if the checksum file is missing.

    4. **Visualization:**

    ```mermaid
    graph LR
        A[Start download.sh] --> B{Check SHA256 file HTTP status code};
        B -- 200 OK --> C[Download SHA256 file];
        B -- 404 Not Found --> D[Skip Checksum Validation];
        C --> E[Download Binary];
        E --> F[Validate Checksum];
        F -- Checksum OK --> G[Install Binary];
        F -- Checksum Fail --> H[Exit with Error];
        D --> E;
        G --> I[End download.sh];
        H --> I;
        I --> J[Package Extension];
        J --> K[Distribute Extension];
        K --> L{User Installs Extension with potentially malicious binary};
    ```

- **Security Test Case:**
    1. **Pre-setup (Attacker):**
        - **Compromise `infracost.io`:** Gain control over the server hosting `infracost.io/downloads/latest`.
        - **Replace Binary:** Replace the legitimate Infracost CLI binary (e.g., `infracost-linux-amd64`) with a malicious binary. The malicious binary could be a simple script that echoes "Malicious binary executed" and sleeps for a few seconds to simulate normal execution.
        - **Remove Checksum File:** Delete the corresponding SHA256 checksum file (e.g., `infracost-linux-amd64.tar.gz.sha256`) from the server.
    2. **Victim Setup:**
        - **Clean Environment:** Ensure a clean VSCode development environment where the Infracost extension is not yet installed or can be cleanly re-installed.
        - **Download Extension Source Code:** Clone the VSCode Infracost extension repository to a local machine.
    3. **Modify `download.sh` (Optional but helpful for testing):**
        - For easier verification, modify the `download.sh` script to output the path of the downloaded binary after the script completes. Add `echo "Downloaded binary path: bin/infracost"` at the end of the script.
    4. **Package the Extension:**
        - Navigate to the extension's root directory in the terminal.
        - Run the command to package the extension (e.g., `yarn vscode:package`). This command should execute the `download.sh` script as part of the packaging process.
    5. **Install the Packaged Extension:**
        - Install the newly packaged `.vsix` file in VSCode.
    6. **Execute Extension Functionality:**
        - Open a Terraform project in VSCode.
        - Trigger the Infracost extension, for example, by opening a Terraform file or refreshing the Infracost project tree. This will cause the extension to execute the downloaded Infracost CLI binary.
    7. **Verify Malicious Binary Execution:**
        - Check the output of the Infracost extension (e.g., in the "Infracost Debug" output channel or in a terminal if the malicious binary writes to stdout).
        - If the malicious binary replaced the legitimate one, you should see the "Malicious binary executed" message (or equivalent output from your malicious binary) in the output, indicating successful execution of the compromised binary.
        - If you modified `download.sh` to output the binary path, verify that the executed binary is indeed the one downloaded by the script.