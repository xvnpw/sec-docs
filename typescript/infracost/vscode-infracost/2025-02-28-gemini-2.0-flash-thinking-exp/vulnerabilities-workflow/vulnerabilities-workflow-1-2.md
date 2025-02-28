### Vulnerability List

- Vulnerability Name: Checksum validation bypass in download script
- Description:
  The `download.sh` script is used to download the Infracost CLI binary.
  It attempts to validate the downloaded binary using a checksum file (`.sha256`).
  However, if the request to fetch the checksum file returns an HTTP 404 error (Not Found), the script incorrectly assumes that checksum validation is not needed and proceeds to install the binary without any validation.
  This allows a potential attacker to bypass the checksum validation mechanism.

  Steps to trigger vulnerability:
  1. The `download.sh` script attempts to download the Infracost CLI binary and its corresponding checksum file from `https://infracost.io/downloads/latest`.
  2. The script checks the HTTP status code when requesting the checksum file (`.sha256`).
  3. If the HTTP status code is 404 (Not Found), the script prints "Skipping checksum validation as the sha for the release could not be found, no action needed."
  4. The script then proceeds to extract and install the downloaded binary without verifying its integrity using the checksum.

- Impact:
  An attacker capable of performing a man-in-the-middle (MITM) attack or compromising the `infracost.io` server could remove or prevent access to the `.sha256` checksum file.
  This would force the `download.sh` script to skip checksum validation and install a potentially malicious Infracost CLI binary.
  If a malicious binary is installed, it could lead to arbitrary code execution on the user's machine when the VSCode extension executes the Infracost CLI.
  This could allow the attacker to gain full control over the user's system, steal sensitive information, or perform other malicious actions.

- Vulnerability Rank: high

- Currently Implemented Mitigations:
  The script attempts to perform checksum validation using `shasum -sc` when the `.sha256` file is successfully downloaded.

- Missing Mitigations:
  The script should treat a 404 error when fetching the `.sha256` file as a critical error and halt the installation process.
  Instead of skipping validation, the script should fail securely and inform the user about the inability to verify the integrity of the downloaded binary.
  Ideally, the script should enforce checksum validation and not proceed if the checksum file is missing or invalid.

- Preconditions:
  1. The user must execute the `download.sh` script. This script is provided in the README and quick start guide, so users are encouraged to run it.
  2. An attacker must be able to cause an HTTP 404 error when the `download.sh` script attempts to download the `.sha256` checksum file from `https://infracost.io/downloads/latest`. This could be achieved through:
     - A man-in-the-middle attack that intercepts the request for the `.sha256` file and returns a 404 response.
     - Compromising the `infracost.io` server and removing or making the `.sha256` file inaccessible.

- Source Code Analysis:
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
  - Line `code=$(curl -s -L -o /dev/null -w "%{http_code}" "$url/$tar.sha256")`: This line attempts to get the HTTP status code of the request for the checksum file.
  - Line `if [ "$code" = "404" ]; then`: This condition checks if the status code is 404.
  - Line `echo "Skipping checksum validation as the sha for the release could not be found, no action needed."`: If the condition is true (404), this message is printed, indicating that checksum validation is skipped.
  - The script then proceeds to install the binary without checksum validation in the `else` block.
  - This logic is flawed as it fails to enforce checksum validation when the checksum file is not available, opening up a security vulnerability.

- Security Test Case:
  1. **Prerequisites:** You need a machine where you can run the `download.sh` script and a way to simulate a 404 error for the checksum file request. You can use a proxy tool like `mitmproxy` or `Burp Suite` to intercept and modify HTTP responses.
  2. **Setup Proxy (Optional):** Configure your system to use a proxy (e.g., `mitmproxy`).
  3. **Run Download Script:** Execute the `download.sh` script. Observe the output; it should download and validate the checksum if the `.sha256` file is available.
  4. **Intercept Checksum Request:** Using your proxy tool (or by directly modifying server response if you control the server), intercept the HTTP request for the checksum file (`https://infracost.io/downloads/latest/infracost-<os-arch>.tar.gz.sha256`).
  5. **Return 404 Response:** Configure the proxy to return an HTTP 404 Not Found response for the checksum file request.
  6. **Run Download Script Again:** Execute the `download.sh` script again.
  7. **Verify Bypass:** Observe the output. You should see the message "Skipping checksum validation as the sha for the release could not be found, no action needed.".
  8. **Verify Installation (Optional but Recommended):** Check that the Infracost CLI binary is installed in the `bin` directory. To further verify the vulnerability, you could replace the actual Infracost CLI binary on the server (if you control it) with a harmless malicious script (e.g., one that simply prints a message and exits). After running the `download.sh` script with the 404 response, executing the installed `infracost` binary should run your malicious script, demonstrating successful bypass and potential for malicious code execution.

This test case proves that the checksum validation can be bypassed by causing a 404 error when requesting the checksum file, confirming the vulnerability.