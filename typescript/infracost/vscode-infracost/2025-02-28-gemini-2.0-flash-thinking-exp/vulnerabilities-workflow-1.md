## Combined Vulnerability List

### Insecure Download and Checksum Bypass of CLI in `download.sh`

- **Vulnerability Name:** Insecure Download and Checksum Bypass of CLI in `download.sh`
- **Description:**
    - The `download.sh` script is responsible for downloading the `infracost` CLI binary from `infracost.io/downloads/latest`.
    - The script uses `curl -sL` to fetch the binary and its SHA256 checksum file.
    - **Insecure Download via HTTP Redirection:** While the initial download URL `https://infracost.io/downloads/latest` uses HTTPS, the `curl -sL` command does not explicitly enforce HTTPS for all subsequent redirects. This can allow a Man-in-the-Middle (MITM) attacker to downgrade the connection to HTTP during a redirect, potentially leading to the download of a compromised binary.
    - **Checksum Validation Bypass on 404:** The script attempts to validate the downloaded binary using a SHA256 checksum file. However, if the request to fetch the checksum file (`.sha256`) returns an HTTP 404 error (Not Found), the script incorrectly assumes that checksum validation is not necessary and proceeds to install the binary without any verification. This can happen due to temporary server unavailability, misconfiguration, or a MITM attacker preventing access to the checksum file.
    - **MITM Attack Scenario:** A MITM attacker can intercept the download request and redirect it to a malicious server. This malicious server can serve a compromised `infracost` binary and either a corresponding malicious checksum file (for MITM on HTTPS downgrade) or ensure the checksum file request returns a 404 error (to trigger checksum bypass).
    - **404 Bypass Scenario:** If the infracost.io server, either legitimately or due to a compromise, fails to serve the `.sha256` checksum file (returns 404), the script will skip checksum validation entirely and install the binary as is.
    - In both scenarios, after download (potentially malicious and unchecked), the `download.sh` script extracts and installs the binary in the `bin` directory of the VSCode extension.

- **Impact:**
    - Execution of arbitrary code on the user's machine with the privileges of the VSCode extension.
    - This can lead to:
        - Data theft, including sensitive information from the user's workspace and environment.
        - System compromise, allowing the attacker to gain persistent access to the user's machine.
        - Installation of malware or further malicious components.
        - In the context of VSCode extension, this can lead to exfiltration of secrets, source code, or even control over the developer's environment.

- **Vulnerability Rank:** High

- **Currently Implemented Mitigations:**
    - Checksum validation of the downloaded binary using SHA256 is attempted.
    - The script tries to download the SHA256 checksum file and validate the downloaded binary against it using `shasum -sc` if the checksum file is successfully downloaded (HTTP status code is not 404).

- **Missing Mitigations:**
    - **Enforce HTTPS for download URLs**: Ensure that `curl` commands explicitly enforce HTTPS for all download URLs, including redirects, to prevent protocol downgrade attacks. Use `curl --proto https` or similar mechanisms.
    - **Strict 404 Handling for Checksum**: Treat a 404 error when fetching the `.sha256` file as a critical error. The script should fail securely and halt the installation process instead of skipping validation.
    - **Mandatory Checksum Validation**: Enforce checksum validation as a mandatory step. Do not proceed with the installation if the checksum file is missing, invalid, or if validation fails.
    - **Integrity Check with Trusted Key**: Consider using a more robust integrity check mechanism, such as GPG signatures verified against a trusted public key embedded in the extension, to ensure the authenticity and integrity of the downloaded binary beyond just checksums.
    - **Strict Transport Security (HSTS)**: While not directly in the script, ensure that `infracost.io` uses HSTS to prevent protocol downgrade attacks in browsers and other clients accessing the download links.

- **Preconditions:**
    - The user must run the `download.sh` script. This script is referenced in the README and quick start guide, making it likely for users to execute it for setup.
    - **For MITM:** The user must be in a network environment where a MITM attack is possible, such as a public Wi-Fi network or a compromised network. The attacker needs to be able to intercept network traffic between the user's machine and `infracost.io`.
    - **For 404 Bypass:** The `.sha256` file for the latest release is not available at the expected URL on `infracost.io` when the `download.sh` script is executed, or a MITM attacker can cause a 404 response for the checksum file request.

- **Source Code Analysis:**
    - File: `/code/scripts/download.sh`
    - Line 20: `url="https://infracost.io/downloads/latest"` - Defines the base URL for downloads, using HTTPS initially.
    - Line 23: `curl -sL "$url/$tar" -o "/tmp/$tar"` - Downloads the `infracost` binary. The `-sL` options for `curl` are used for silent mode and following redirects, but it **does not enforce HTTPS** for redirects, allowing potential downgrade to HTTP.
    - Line 27: `curl -s -L -o /dev/null -w "%{http_code}" "$url/$tar.sha256"` - Checks if the SHA256 file exists by fetching HTTP status code.
    - Line 31: `curl -sL "$url/$tar.sha256" -o "/tmp/$tar.sha256"` - Downloads the SHA256 checksum file. Similar to binary download, HTTPS is not enforced for redirects.
    - Line 34: `if ! check_sha "$tar.sha256"; then` - Validates the checksum, but this validation is conditional and bypassed if the checksum file is not found (404).
    - Line 28-35:
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
      This code block shows the flawed logic: a 404 on the checksum file leads to skipping validation instead of failing.

    - **Visualization (MITM Attack):**
        ```
        User's Machine ---[HTTPS Request to infracost.io/downloads/latest]--- MITM Attacker ---[Forwards Request to infracost.io]--- infracost.io
        User's Machine <---[HTTP Redirect to malicious server]--- MITM Attacker <---[Redirect from infracost.io OR directly from MITM]--- infracost.io (or Malicious Server)
        User's Machine ---[HTTP Request to malicious server]--- MITM Attacker ---[Forwards (or not) to Malicious Server]--- Malicious Server
        User's Machine <---[HTTP Response with malicious binary and checksum]--- MITM Attacker <---[Response from Malicious Server]--- Malicious Server
        User's Machine (Checksum validation passes for malicious binary OR is skipped if attacker manipulates checksum availability)
        User's Machine (Malicious binary installed and potentially executed)
        ```

- **Security Test Case:**
    1. **Prerequisites:** Install `mitmproxy` (or similar MITM proxy) and a simple HTTP server (e.g., using Python's `http.server`). Have access to a network where you can intercept and modify traffic.
    2. **Setup MITM Proxy:** Configure `mitmproxy` to listen on port 8080 and intercept traffic. Set your system's HTTP/HTTPS proxy to `http://127.0.0.1:8080`.
    3. **Create Malicious Server:** Set up an HTTP server serving a malicious `infracost` binary and a corresponding SHA256 checksum file at paths mimicking `infracost.io/downloads/latest/`. For example, for `infracost-linux-amd64.tar.gz`, serve files at `/downloads/latest/infracost-linux-amd64.tar.gz` and `/downloads/latest/infracost-linux-amd64.tar.gz.sha256`.
    4. **Run `download.sh` with Proxy Enabled:** Execute `download.sh` while `mitmproxy` is running.
    5. **(Test Case A: MITM and Checksum Bypass/Manipulation)** In `mitmproxy`, intercept requests to `infracost.io/downloads/latest`. Configure `mitmproxy` to redirect requests to `infracost.io/downloads/latest` to your malicious server (`http://127.0.0.1:<malicious_server_port>/downloads/latest`). Ensure your malicious server serves both binary and checksum or is configured to return 404 for checksum to test bypass.
    6. **(Test Case B: 404 Checksum Bypass)** Alternatively, for 404 bypass test, you can configure `mitmproxy` to intercept requests specifically for the `.sha256` file (`infracost.io/downloads/latest/*.sha256`) and return a 404 HTTP response. Leave the binary download request to proceed to the legitimate server (or a malicious one if you want to combine MITM and 404).
    7. **Verify Malicious Binary Download:** After running `download.sh`, check the `bin` directory within the VSCode extension's folder. Confirm that the downloaded `infracost` binary is the malicious one (check file hash, timestamp, or content). In the 404 bypass case, even if you used the legitimate binary on the malicious server, the lack of checksum validation is the vulnerability.
    8. **(Optional) Further Exploitation (Safe Environment Only):** If using a harmless-malicious binary, trigger the VSCode extension to execute `infracost`. Verify if your malicious code runs, confirming arbitrary code execution.
    9. **(Verification of 404 Bypass):** In the 404 test case (Test Case B), observe the output of `download.sh`. It should show "Skipping checksum validation as the sha for the release could not be found, no action needed.", confirming the bypass is triggered.

This combined test case demonstrates both the MITM vulnerability due to lack of HTTPS enforcement and the checksum validation bypass on 404, highlighting the insecure download process in `download.sh`.