### Vulnerability List

- Vulnerability Name: MITM Attack during CLI Download
- Description:
    - The `download.sh` script is used to download the `infracost` CLI binary from `infracost.io`.
    - The script uses `curl -sL` to download the binary and its SHA256 checksum.
    - Although the download URL `https://infracost.io/downloads/latest` uses HTTPS, the `curl` command in the script does not explicitly enforce HTTPS.
    - A Man-in-the-Middle (MITM) attacker could intercept the download request and redirect it to a malicious server.
    - This malicious server could serve a compromised `infracost` binary and a corresponding (or modified) SHA256 checksum file.
    - The `download.sh` script would then download the malicious binary and its checksum.
    - The checksum validation in the script would pass because the malicious checksum matches the malicious binary.
    - Consequently, the compromised `infracost` binary would be installed in the `bin` directory of the VSCode extension.
- Impact:
    - Execution of arbitrary code on the user's machine with the privileges of the VSCode extension.
    - This can lead to:
        - Data theft, including sensitive information from the user's workspace and environment.
        - System compromise, allowing the attacker to gain persistent access to the user's machine.
        - Installation of malware or further malicious components.
- Vulnerability Rank: High
- Currently Implemented Mitigations:
    - Checksum validation of the downloaded binary using SHA256.
    - The script attempts to download SHA256 checksum file and validate the downloaded binary against it.
- Missing Mitigations:
    - **Enforce HTTPS for download URLs**: Ensure that `curl` commands explicitly enforce HTTPS for all download URLs to prevent protocol downgrade attacks.
    - **Strict Transport Security (HSTS)**: While not directly in the script, ensure that `infracost.io` uses HSTS to prevent protocol downgrade attacks in browsers and other clients.
    - **Integrity Check with Trusted Key**: Consider using a more robust integrity check mechanism, such as GPG signatures verified against a trusted public key embedded in the extension, to ensure the authenticity and integrity of the downloaded binary.
- Preconditions:
    - The user must run the `download.sh` script. This script is mentioned in the README and quick start guide, so users might execute it.
    - The user must be in a network environment where a MITM attack is possible. This could be a public Wi-Fi network or a compromised network.
    - The attacker needs to be able to intercept network traffic between the user's machine and `infracost.io`.
    - The attacker needs to set up a malicious server that mimics the `infracost.io` download structure and serves a malicious `infracost` binary and a corresponding (or modified) SHA256 checksum file.
- Source Code Analysis:
    - File: `/code/scripts/download.sh`
    - Line 20: `url="https://infracost.io/downloads/latest"` - Defines the base URL for downloads, using HTTPS.
    - Line 23: `curl -sL "$url/$tar" -o "/tmp/$tar"` - Downloads the `infracost` binary. The `-sL` options for `curl` are used for silent mode and following redirects, but it does not enforce HTTPS for the entire connection, including redirects.
    - Line 27: `curl -s -L -o /dev/null -w "%{http_code}" "$url/$tar.sha256"` - Checks if the SHA256 file exists.
    - Line 31: `curl -sL "$url/$tar.sha256" -o "/tmp/$tar.sha256"` - Downloads the SHA256 checksum file. Similar to the binary download, HTTPS is not enforced.
    - Line 34: `if ! check_sha "$tar.sha256"; then` - Validates the checksum.
    - Visualization:
        ```
        User's Machine ---[HTTP/HTTPS Request to infracost.io/downloads/latest]--- MITM Attacker ---[Forwards Request to infracost.io]--- infracost.io
        User's Machine <---[HTTP/HTTPS Redirect to malicious server]--- MITM Attacker <---[Redirect from infracost.io OR directly from MITM]--- infracost.io (or Malicious Server)
        User's Machine ---[HTTP Request to malicious server]--- MITM Attacker ---[Forwards (or not) to Malicious Server]--- Malicious Server
        User's Machine <---[HTTP Response with malicious binary and checksum]--- MITM Attacker <---[Response from Malicious Server]--- Malicious Server
        User's Machine (Checksum validation passes for malicious binary)
        User's Machine (Malicious binary installed and potentially executed)
        ```
- Security Test Case:
    1. **Prerequisites:** Install `mitmproxy` or a similar MITM proxy tool. Have access to a network where you can intercept and modify traffic.
    2. **Setup MITM Proxy:** Configure `mitmproxy` to listen on a specific port (e.g., 8080) and to intercept traffic. Configure your system's network settings to route traffic through `mitmproxy` (e.g., set HTTP/HTTPS proxy to `http://127.0.0.1:8080`).
    3. **Create Malicious Server:** Set up a simple HTTP server (e.g., using Python's `http.server`) that will serve a malicious `infracost` binary and a corresponding SHA256 checksum file. These files should be accessible at paths mimicking the structure of `infracost.io/downloads/latest`. For example, if the script is downloading `infracost-linux-amd64.tar.gz`, your malicious server should serve the malicious binary at `/downloads/latest/infracost-linux-amd64.tar.gz` and the checksum at `/downloads/latest/infracost-linux-amd64.tar.gz.sha256`. You can create a dummy malicious binary and generate its SHA256 checksum.
    4. **Run `download.sh` with Proxy Enabled:** Execute the `download.sh` script in your terminal while `mitmproxy` is running and intercepting traffic.
    5. **Intercept and Redirect in `mitmproxy`:** Configure `mitmproxy` to intercept requests to `infracost.io/downloads/latest` and redirect them to your malicious server. You can use `mitmproxy`'s interception and redirection features to achieve this. For example, redirect requests for `infracost.io/downloads/latest` to `http://127.0.0.1:<malicious_server_port>/downloads/latest`.
    6. **Verify Malicious Binary Download:** After running `download.sh`, check the `bin` directory within the VSCode extension's folder. Verify that the downloaded `infracost` binary is indeed the malicious binary you served from your malicious server. You can check file hashes or timestamps to confirm.
    7. **(Optional) Further Exploitation (if safe to do so):** If you have created a truly malicious binary (for testing purposes only and in a safe, isolated environment!), you can try to run the VSCode extension and observe if the malicious `infracost` binary is executed as part of the extension's functionality. This would further demonstrate the impact of the vulnerability.

This test case demonstrates how a MITM attacker could exploit the lack of enforced HTTPS in `download.sh` to serve a malicious binary, bypassing the checksum validation and potentially compromising the user's system.