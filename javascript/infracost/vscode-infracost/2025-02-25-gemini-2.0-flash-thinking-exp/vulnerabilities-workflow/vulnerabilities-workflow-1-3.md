### Vulnerability List:

- Vulnerability Name: Insecure Binary Download without Checksum Validation
- Description:
    The `download.sh` script is used to download the `infracost` CLI binary.
    This script attempts to validate the downloaded binary using a SHA256 checksum file.
    However, if the SHA256 checksum file is not found on the server (resulting in a HTTP 404 error), the script proceeds to install the binary without performing any checksum validation.
    An attacker could potentially compromise the download server (`infracost.io/downloads/latest`) and replace the legitimate `infracost` binary with a malicious one.
    By ensuring that the SHA256 file is unavailable (e.g., by removing it or causing a 404 error), the attacker can force the `download.sh` script to skip checksum validation and install the malicious binary on the user's system.
    This can be triggered by an external attacker compromising the `infracost.io` domain or its CDN.

    **Step-by-step trigger:**
    1. Attacker compromises the `infracost.io` domain or its CDN.
    2. Attacker replaces the legitimate `infracost-<target>.tar.gz` binary with a malicious one on the server.
    3. Attacker ensures that the SHA256 checksum file `infracost-<target>.tar.gz.sha256` is not available on the server, so that accessing it returns a 404 Not Found error.
    4. User follows the official documentation or README and executes the `download.sh` script to install the Infracost CLI.
    5. The `download.sh` script downloads the malicious `infracost-<target>.tar.gz` because the server is compromised.
    6. The script checks for the SHA256 file by sending a request to `https://infracost.io/downloads/latest/infracost-<target>.tar.gz.sha256`.
    7. The server responds with a 404 Not Found error for the SHA256 file.
    8. The `download.sh` script interprets the 404 error as a signal to skip checksum validation, as per the script's logic.
    9. The script proceeds to extract and install the malicious binary without validation.
    10. User's system is now compromised with the malicious binary.

- Impact:
    Successful exploitation of this vulnerability allows an attacker to execute arbitrary code on the user's machine.
    This can lead to a wide range of severe consequences, including:
    - Data theft: The attacker can steal sensitive information stored on the user's system or accessible by the user.
    - System compromise: The attacker can gain complete control over the user's system, potentially installing persistent backdoors, malware, or ransomware.
    - Privilege escalation: If the user runs the script with elevated privileges (e.g., as root or administrator), the attacker can gain those elevated privileges as well.
    - Supply chain attack: This can be considered a supply chain vulnerability as users are instructed to use this script to install a prerequisite component.

- Vulnerability Rank: High

- Currently implemented mitigations:
    The `download.sh` script attempts to perform SHA256 checksum validation.
    It downloads the SHA256 file and uses `shasum -sc` to verify the downloaded archive.
    However, the script's logic explicitly skips this validation if the SHA256 file is not found (404 response).

    ```sh
    code=$(curl -s -L -o /dev/null -w "%{http_code}" "$url/$tar.sha256")
    if [ "$code" = "404" ]; then
      echo "Skipping checksum validation as the sha for the release could not be found, no action needed."
    else
      # ... checksum validation logic ...
    fi
    ```

- Missing mitigations:
    - **Mandatory Checksum Validation:** The script should enforce checksum validation. If the SHA256 file is not found or if the checksum validation fails, the script should abort the installation process and display an error message to the user. Skipping checksum validation on a 404 response is insecure.
    - **Error Handling Improvement:** Instead of treating a 404 for the checksum file as a non-critical issue, the script should treat it as a critical error that prevents secure installation.
    - **Alternative Checksum Source:** Consider embedding the checksum within the script itself or fetching it from a more reliable and separate source (e.g., a dedicated security endpoint or a signed manifest).

- Preconditions:
    - The user must execute the `download.sh` script to install the Infracost CLI.
    - The attacker must have successfully compromised the `infracost.io` domain or its CDN to replace the binary.
    - The attacker must ensure that the SHA256 checksum file for the malicious binary is unavailable on the server, causing a 404 error when the script attempts to fetch it.

- Source code analysis:
    ```sh
    #!/usr/bin/env sh
    # ...
    url="https://infracost.io/downloads/latest"
    tar="infracost-$bin_target.tar.gz"
    # ...
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
    # ...
    tar xzf "/tmp/$tar" -C /tmp
    # ...
    ```

    The code snippet above shows the vulnerable logic.
    1. **`code=$(curl -s -L -o /dev/null -w "%{http_code}" "$url/$tar.sha256")`**: This line attempts to fetch the HTTP status code when requesting the SHA256 file. `-w "%{http_code}"` specifically extracts the HTTP status code. `-o /dev/null` discards the response body as only the status code is needed.
    2. **`if [ "$code" = "404" ]; then`**: This condition checks if the HTTP status code is 404 (Not Found).
    3. **`echo "Skipping checksum validation as the sha for the release could not be found, no action needed."`**: If the condition is true (404), this message is printed, and the script proceeds **without** checksum validation.
    4. **`else ... fi`**: If the status code is not 404 (meaning the SHA256 file is found), the script proceeds to download the SHA256 file, perform the checksum validation using `check_sha`, and exit with an error if validation fails. However, in the case of a 404, this entire validation block is skipped, making the script vulnerable.
    5. **`tar xzf "/tmp/$tar" -C /tmp`**: This line extracts the downloaded archive. If the SHA256 validation was skipped due to a 404, and the downloaded archive is malicious, this line will install the malicious binary.

- Security test case:
    1. **Set up a malicious server or proxy:** Configure a web server or proxy that can intercept requests to `infracost.io/downloads/latest`. For testing purposes, you can use tools like `mitmproxy` or set up a simple HTTP server using Python or Node.js.
    2. **Prepare malicious binary and archive:** Create a malicious version of the `infracost` binary (e.g., a simple script that prints a warning and then exits). Package this malicious binary into a `infracost-<target>.tar.gz` archive, mimicking the legitimate archive structure.
    3. **Configure malicious server response:** Configure your malicious server or proxy to respond to requests for `https://infracost.io/downloads/latest/infracost-<target>.tar.gz` with the malicious archive you created.
    4. **Configure 404 response for SHA256:** Ensure that when the `download.sh` script requests `https://infracost.io/downloads/latest/infracost-<target>.tar.gz.sha256`, the server responds with a HTTP 404 Not Found error. This can be achieved by simply not hosting the SHA256 file on your malicious server.
    5. **Modify `download.sh` for testing (optional but recommended for isolation):**  For isolated testing, you can temporarily modify the `download.sh` script to point to your malicious server instead of `infracost.io`. Change the `url` variable in the script to your malicious server's URL.
    6. **Run the `download.sh` script:** Execute the modified `download.sh` script on a test machine.
    7. **Observe skipped validation and malicious binary installation:** Observe the output of the script. You should see the message "Skipping checksum validation as the sha for the release could not be found, no action needed." This indicates that the checksum validation was bypassed.
    8. **Verify execution of malicious code:** After the script completes, attempt to run the installed `infracost` binary. Verify that your malicious code (e.g., the warning message you added) is executed, confirming that the malicious binary was installed due to the bypassed checksum validation.

This test case demonstrates how an attacker can exploit the insecure checksum handling in `download.sh` to install a malicious binary by ensuring the SHA256 file is unavailable, leading to a 404 error and skipped validation.