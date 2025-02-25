### Vulnerability List

- Vulnerability Name: Insecure Binary Download due to Conditional Checksum Validation
- Description: The `download.sh` script downloads the Infracost CLI binary from `infracost.io`. While it attempts to validate the download using a SHA256 checksum, this validation is conditional. If the SHA256 checksum file is not found on the server (returns a 404 error), the script skips the checksum validation entirely and proceeds to use the downloaded binary. An attacker performing a man-in-the-middle (MITM) attack could exploit this by ensuring that the checksum file is unavailable (e.g., by blocking requests to the checksum file URL). This would force the script to skip validation, allowing the attacker to replace the legitimate binary with a malicious one.
- Impact: If successful, the attacker can replace the Infracost CLI binary with a malicious executable. When the VS Code extension executes the downloaded binary, it would run the attacker's malicious code, potentially leading to command execution, data theft, or other forms of system compromise on the user's machine.
- Vulnerability Rank: High
- Currently Implemented Mitigations: Checksum validation is attempted, but it is conditional and skipped if the checksum file is not found.
- Missing Mitigations:
    - Checksum validation should be mandatory. The download process should fail if the checksum file is not available or if checksum validation fails.
    - Consider implementing binary signature verification in addition to checksum validation to enhance trust in the downloaded binary.
- Preconditions:
    - The user must run the VS Code extension in an environment where a man-in-the-middle attack is possible (e.g., on a compromised network).
    - The `INFRACOST_BIN_TARGET` environment variable is not set to point to a pre-existing, trusted Infracost binary.
- Source Code Analysis:
    - File: `/code/scripts/download.sh`
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
    - The vulnerability lies in the conditional checksum validation.
    - The script uses `curl` to get the HTTP status code when requesting the SHA256 checksum file.
    - If the status code is `404` (Not Found), the script explicitly skips the checksum validation process and proceeds with using the downloaded binary.
    - This allows an attacker to bypass the checksum validation by ensuring that the checksum file is unavailable, for example, by blocking requests to the checksum file URL in a MITM attack scenario.

- Security Test Case:
    1. Set up a Man-In-The-Middle (MITM) proxy like `mitmproxy` or `Burp Suite`. Configure your system to route traffic through this proxy.
    2. Configure the MITM proxy to intercept HTTPS requests to `infracost.io`.
    3. Within the proxy configuration, set up a rule to specifically target requests for SHA256 checksum files (e.g., requests ending in `.sha256` under `infracost.io/downloads/latest/`).
    4. Configure the proxy to respond to these checksum file requests with an HTTP 404 Not Found status code. This simulates the checksum file not being available on the server.
    5. In VS Code, open a workspace that triggers the Infracost extension to download the CLI binary. This might happen on the first run of the extension or when the Infracost CLI binary is missing from the expected location.
    6. Observe the output in the "Infracost Debug" output panel in VS Code (Terminal -> Output -> Infracost Debug). You should see the message "Skipping checksum validation as the sha for the release could not be found, no action needed." in the logs, confirming that the checksum validation was bypassed.
    7. To further verify the exploit, you can configure the MITM proxy to also replace the binary archive (`infracost-<target>.tar.gz`) with a malicious archive containing a reverse shell or any other form of malicious code.
    8. After the extension downloads and extracts the (malicious) binary, attempt to use the Infracost extension in VS Code, which will execute the downloaded (and now malicious) `infracost` binary. Verify that the malicious code is executed. For example, if you included a reverse shell, you should receive a connection from the target machine.

This test case demonstrates that by manipulating network traffic and ensuring the checksum file is unavailable, an attacker can force the `download.sh` script to skip checksum validation and potentially replace the legitimate Infracost CLI binary with a malicious one, leading to arbitrary code execution on the user's machine.