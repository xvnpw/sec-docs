Here is the combined list of vulnerabilities, removing duplicates and formatted as markdown:

### Insecure Binary Download due to Conditional Checksum Validation

- **Vulnerability Name:** Insecure Binary Download due to Conditional Checksum Validation

- **Description:**
    The `download.sh` script downloads the Infracost CLI binary from `infracost.io`. While it attempts to validate the download using a SHA256 checksum, this validation is conditional. If the SHA256 checksum file is not found on the server (returns a 404 error), the script skips the checksum validation entirely and proceeds to use the downloaded binary. An attacker performing a man-in-the-middle (MITM) attack, or who has compromised the `infracost.io` domain or its CDN, could exploit this.  By ensuring that the checksum file is unavailable (e.g., by blocking requests to the checksum file URL in a MITM attack, or removing/making inaccessible the checksum file on a compromised server), the attacker forces the script to skip validation, allowing the attacker to replace the legitimate binary with a malicious one.

    **Step-by-step trigger (Compromised Server Scenario):**
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

- **Impact:**
    If successful, the attacker can replace the Infracost CLI binary with a malicious executable. When the VS Code extension or a user executes the downloaded binary, it would run the attacker's malicious code, potentially leading to command execution, data theft, or other forms of system compromise on the user's machine. This can lead to a wide range of severe consequences, including:
    - Data theft: The attacker can steal sensitive information stored on the user's system or accessible by the user.
    - System compromise: The attacker can gain complete control over the user's system, potentially installing persistent backdoors, malware, or ransomware.
    - Privilege escalation: If the user runs the script with elevated privileges (e.g., as root or administrator), the attacker can gain those elevated privileges as well.
    - Supply chain attack: This can be considered a supply chain vulnerability as users are instructed to use this script to install a prerequisite component.

- **Vulnerability Rank:** High

- **Currently Implemented Mitigations:**
    Checksum validation is attempted using SHA256. The `download.sh` script attempts to download a `.sha256` file from the same location as the binary and uses `shasum -sc` to verify the downloaded archive. HTTPS is used for downloading both the tarball and checksum file, ensuring encrypted communication. However, the checksum validation is conditional and skipped if the checksum file is not found (HTTP 404 status code).

    ```sh
    code=$(curl -s -L -o /dev/null -w "%{http_code}" "$url/$tar.sha256")
    if [ "$code" = "404" ]; then
      echo "Skipping checksum validation as the sha for the release could not be found, no action needed."
    else
      # ... checksum validation logic ...
    fi
    ```

- **Missing Mitigations:**
    - **Mandatory Checksum Validation:** Checksum validation should be mandatory. The download process should fail if the checksum file is not available (HTTP 404) or if checksum validation fails. Skipping checksum validation on a 404 response is insecure.
    - **Error Handling Improvement:** Instead of treating a 404 for the checksum file as a non-critical issue, the script should treat it as a critical error that prevents secure installation and abort the installation process with a clear error message to the user.
    - **Alternative Checksum Source:** Consider embedding the checksum directly within the script, or fetching it from a more reliable and separate source, such as a dedicated security endpoint, a signed manifest, or an out-of-band published hash.
    - **Binary Signature Verification:** Consider implementing binary signature verification in addition to checksum validation to enhance trust in the downloaded binary and ensure its authenticity and integrity beyond just file corruption.
    - **Fallback Verification Mechanism:** Implement a fallback verification mechanism (such as a hard-coded checksum value or an out‑of-band published hash) to validate the binary in the event of a missing checksum file online.
    - **Certificate Pinning:** Implement certificate pinning or additional transport security measures to reduce the trust placed solely on the HTTPS connection and the remote server’s availability of the checksum file.

- **Preconditions:**
    - The user must run the `download.sh` script manually or the VS Code extension must trigger the script to download the Infracost CLI binary.
    - An attacker must be able to intercept or manipulate the network traffic between the user and `https://infracost.io/downloads/latest` in such a way that the request for the checksum file returns a 404 status or an attacker-controlled response (Man-In-The-Middle attack).
    - Alternatively, the attacker must have successfully compromised the `infracost.io` domain or its CDN to replace the binary and remove/make inaccessible the checksum file.
    - The `INFRACOST_BIN_TARGET` environment variable is not set to point to a pre-existing, trusted Infracost binary.

- **Source Code Analysis:**
    - File: `/code/scripts/download.sh`
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
    - The vulnerability lies in the conditional checksum validation logic within the `download.sh` script.
    - The script uses `curl` to get the HTTP status code when requesting the SHA256 checksum file (`$url/$tar.sha256`).
    - **Conditional Checksum Bypass:** If the HTTP status code returned for the checksum file request is `404` (Not Found), the script enters the `if` block and explicitly skips the checksum validation process. It prints a misleading message "Skipping checksum validation as the sha for the release could not be found, no action needed." and proceeds with the installation.
    - **Vulnerable Code Flow:**
        ```mermaid
        graph LR
            A[Start: download.sh execution] --> B{Check SHA256 file status code};
            B -- 404 Status Code --> C{Skip Checksum Validation};
            C --> D{Extract and Install Binary};
            B -- Not 404 Status Code --> E{Download SHA256 file};
            E --> F{Perform Checksum Validation};
            F -- Validation Success --> D;
            F -- Validation Fail --> G[Exit with Error];
            D --> H[End: Binary installed (potentially malicious)];
            C --> H;
            G --> I[End: Installation Aborted];
        ```
    - **Exploitable Condition:** An attacker can exploit this conditional logic by ensuring that the SHA256 checksum file is unavailable when the script requests it. This can be achieved through a MITM attack by intercepting and responding with a 404 status for requests to the checksum file, or by compromising the server and removing the checksum file.
    - **Unprotected Installation:**  When the checksum validation is skipped due to the 404 condition, the script proceeds to extract the downloaded archive (`tar xzf "/tmp/$tar" -C /tmp`) and install the binary without verifying its integrity. If an attacker has replaced the legitimate archive with a malicious one, this results in the installation of the malicious binary.

- **Security Test Case:**
    1. **Set up a Man-In-The-Middle (MITM) proxy:** Use tools like `mitmproxy`, `Burp Suite`, or a custom proxy to intercept HTTPS requests. Configure your system to route traffic through this proxy. Alternatively, for testing a compromised server scenario, you can set up a local web server mimicking `infracost.io` and control its responses.
    2. **Configure MITM proxy for Checksum Interception:** Configure the MITM proxy to intercept HTTPS requests to `infracost.io` (or your test server). Specifically target requests for SHA256 checksum files (e.g., requests ending in `.sha256` under `infracost.io/downloads/latest/`).
    3. **Simulate 404 for Checksum File:** Configure the proxy to respond to these checksum file requests with an HTTP 404 Not Found status code. This simulates the checksum file not being available on the server.
    4. **Prepare a Malicious Binary and Archive (Optional):** To verify code execution, create a malicious version of the `infracost` binary (e.g., a script that prints "Malicious binary executed" or sets up a reverse shell). Package this malicious binary into a `infracost-<target>.tar.gz` archive, mimicking the legitimate archive structure. If you skip this step, you will only verify the bypass of checksum, not malicious code execution.
    5. **Configure MITM proxy for Binary Replacement (Optional):** If you prepared a malicious binary, configure the MITM proxy to also replace the binary archive (`infracost-<target>.tar.gz`) with your malicious archive when requested.
    6. **Run the `download.sh` script:** Execute the `download.sh` script on a test machine that is configured to route traffic through your MITM proxy. Or, if testing a compromised server scenario, run the original `download.sh` but against your controlled server.
    7. **Observe "Skipping checksum validation" Message:** Observe the output of the script. You should see the message "Skipping checksum validation as the sha for the release could not be found, no action needed." in the logs, confirming that the checksum validation was bypassed due to the simulated 404 response.
    8. **Verify Malicious Code Execution (If malicious binary was used):** If you replaced the binary with a malicious one, after the script completes, attempt to run the installed `infracost` binary. Verify that your malicious code is executed (e.g., you see "Malicious binary executed" output, or receive a reverse shell connection).
    9. **Verify Legitimate Binary Execution (If no malicious binary was used):** If you did not replace the binary, and just wanted to verify the bypass, run the installed `infracost` binary to ensure it runs (though without checksum verification). In a real exploit scenario, a malicious binary would be placed here.

This test case demonstrates that by manipulating network traffic (MITM) or server responses (compromised server), and ensuring the checksum file is unavailable, an attacker can force the `download.sh` script to skip checksum validation and potentially replace the legitimate Infracost CLI binary with a malicious one, leading to arbitrary code execution on the user's machine.