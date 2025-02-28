### Vulnerability List

* Vulnerability Name: Missing checksum validation for downloaded binary in `download.sh`
* Description:
    The `download.sh` script downloads the `infracost` CLI binary from `https://infracost.io/downloads/latest` without mandatory checksum validation.
    If the checksum file (`.sha256`) is not found during download (determined by a 404 HTTP status code), the script proceeds to use the downloaded binary without verifying its integrity.
    This can occur due to temporary server unavailability, misconfiguration, or incomplete release processes where the checksum file is not published.
* Impact:
    If an attacker compromises `infracost.io` or performs a man-in-the-middle attack, they could replace the `infracost` binary with a malicious one.
    If checksum validation is skipped, the malicious binary will be used by the extension.
    Upon execution of the compromised `infracost` binary by the VSCode extension, arbitrary code execution can occur on the user's machine, potentially leading to data theft, system compromise, or other malicious activities.
* Vulnerability Rank: High
* Currently implemented mitigations:
    The script attempts to download and validate the checksum of the `infracost` binary.
    However, the checksum validation is conditionally skipped if the `.sha256` checksum file is not found on the server (returns a 404 status code).
* Missing mitigations:
    Checksum validation should be mandatory and enforced.
    The `download.sh` script should be modified to:
    - Fail and exit if the `.sha256` checksum file is not found during download.
    - Fail and exit if the downloaded binary's checksum does not match the checksum provided in the `.sha256` file.
    Consider using more robust methods for verifying binary integrity, such as:
    - Code signing of the `infracost` binary.
    - Using a package manager or a dedicated secure update mechanism.
* Preconditions:
    - The `.sha256` file for the latest release is not available on `infracost.io` when the `download.sh` script is executed. This could be due to temporary server issues, misconfiguration, or release process errors.
    - Alternatively, a man-in-the-middle attacker intercepts the download request and can serve both a malicious `infracost` binary and a corresponding (or missing) `.sha256` file.
* Source code analysis:
    1. **Checksum Download Attempt**: The script attempts to download the checksum file using `curl -sL "$url/$tar.sha256" -o "/tmp/$tar.sha256"`.
    2. **HTTP Status Code Check**: It then checks the HTTP status code of the checksum file request using `code=$(curl -s -L -o /dev/null -w "%{http_code}" "$url/$tar.sha256")`.
    3. **Conditional Checksum Validation**: The script uses an `if` condition `if [ "$code" = "404" ]; then` to check if the HTTP status code is 404 (Not Found).
    4. **Skipping Validation**: If the status code is 404, the script executes `echo "Skipping checksum validation as the sha for the release could not be found, no action needed."` and proceeds to download and use the binary without validation.
    5. **Checksum Validation Execution (if available)**: If the status code is not 404, the script proceeds to download the `.sha256` file and attempts to validate the binary using `if ! check_sha "$tar.sha256"; then exit 1; fi`. However, this part is bypassed if the `.sha256` file is not found.

    ```sh
    code=$(curl -s -L -o /dev/null -w "%{http_code}" "$url/$tar.sha256") # Step 2
    if [ "$code" = "404" ]; then                                          # Step 3
      echo "Skipping checksum validation as the sha for the release could not be found, no action needed." # Step 4
    else
      echo "Validating checksum for infracost-$bin_target..."
      curl -sL "$url/$tar.sha256" -o "/tmp/$tar.sha256"

      if ! check_sha "$tar.sha256"; then                                 # Step 5 (only if not 404)
        exit 1
      fi

      rm "/tmp/$tar.sha256"
    fi
    ```

* Security test case:
    1. **Modify `download.sh`**: Edit the `/code/scripts/download.sh` file within the extension's project directory.
    2. **Simulate 404 for Checksum**: Temporarily alter the URL used to download the `.sha256` checksum file within the `download.sh` script to point to a non-existent path. For example, if the original URL is `https://infracost.io/downloads/latest/infracost-linux-amd64.tar.gz.sha256`, change it to `https://infracost.io/downloads/latest/infracost-linux-amd64.tar.gz.sha256.nonexistent`. Keep the binary download URL (`https://infracost.io/downloads/latest/infracost-linux-amd64.tar.gz`) correct.
    3. **Run `download.sh`**: Execute the modified `download.sh` script from a terminal. This script is usually run during the extension's installation or update process, but for testing, you might need to manually trigger it or re-install the extension after modifying the script.
    4. **Observe Output**: Check the output of the script. It should display the message: "Skipping checksum validation as the sha for the release could not be found, no action needed." This confirms that the script is bypassing checksum validation due to the simulated 404 error.
    5. **Replace Binary**: After the script has run, manually replace the downloaded `infracost` binary located in the `bin` directory of the extension (e.g., `/path/to/vscode-extension/bin/infracost`) with a malicious executable. This malicious executable can be a simple script that, for example, creates a file in a temporary directory to indicate successful execution.
    6. **Activate Extension and Trigger Execution**: Activate the VSCode extension and perform actions that would trigger the execution of the `infracost` binary. This could involve opening a Terraform file, refreshing the Infracost project tree, or running any command that relies on the `infracost` CLI.
    7. **Verify Malicious Code Execution**: Check for the indicators of the malicious script's execution. For instance, if the malicious script was set to create a file in `/tmp/pwned`, verify if this file exists. If the malicious code has been executed successfully, it confirms the vulnerability: the extension used a binary without proper checksum validation, allowing for potential compromise via binary replacement.