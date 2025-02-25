- **Vulnerability Name:** Checksum Bypass in Download Script

  - **Description:**  
    The `download.sh` script is designed to download the latest release tarball of the infracost binary and verify its integrity using a SHA‑256 checksum file. The script requests the checksum file from the same base URL as the binary. However, if the checksum file is missing—i.e. when the HTTP request for the `<tar file>.sha256` returns a 404—the script simply logs a message and skips the checksum verification step. An external attacker who is able to influence the network traffic (for example, via a man‑in‑the‑middle attack or DNS manipulation) can force the checksum file lookup to fail (returning 404) and at the same time substitute the tarball with a maliciously crafted archive. As a result, the binary installed by the script might not be authentic, opening the door for arbitrary code execution on the end user’s system.

  - **Impact:**  
    An attacker who successfully exploits this bypass could serve a tampered binary. When users run the compromised binary, it may execute arbitrary code, which can lead to full system compromise, unauthorized access, data theft, or other malicious actions on the host system.

  - **Vulnerability Rank:** High

  - **Currently Implemented Mitigations:**  
    - The script uses HTTPS to download both the tarball and its checksum file, ensuring that the connection is encrypted.
    - A checksum verification is performed if the checksum file is successfully retrieved.

  - **Missing Mitigations:**  
    - Mandatory checksum verification is not enforced: if the checksum file is unavailable (HTTP 404), the script skips the integrity check entirely.
    - There is no fallback verification mechanism (such as a hard-coded checksum value or an out‑of‑band published hash) to validate the binary in the event of a missing checksum file.
    - Certificate pinning or additional transport security measures are not implemented, which increases the trust placed solely on the HTTPS connection and the remote server’s availability of the checksum file.

  - **Preconditions:**  
    - A user is running the `download.sh` script manually to install the infracost binary.
    - An attacker must be able to intercept or manipulate the network traffic between the user and `https://infracost.io/downloads/latest` in such a way that the request for the checksum file returns a 404 status or an attacker-controlled response.
    - The attacker must be able to substitute the legitimate tarball with a malicious one during the download process.

  - **Source Code Analysis:**  
    1. The script sets strict error handling with `set -e`.  
    2. It defines a function `check_sha()` that:
       - Changes directory to `/tmp/`.
       - Uses `shasum -sc "$1"` to verify the checksum against the file provided.
    3. The operating system and architecture are determined and used to compute the target binary name:
       - `bin_target` is derived from either the environment variable `INFRACOST_BIN_TARGET` or the default `$(uname | tr '[:upper:]' '[:lower:]')-$(uname -m | tr '[:upper:]' '[:lower:]')`.
       - The tarball name is built as `tar="infracost-$bin_target.tar.gz"`.
    4. The tarball is downloaded using:  
       `curl -sL "$url/$tar" -o "/tmp/$tar"`
    5. The script then checks if the checksum file exists by:  
       `code=$(curl -s -L -o /dev/null -w "%{http_code}" "$url/$tar.sha256")`
    6. If the HTTP code equals 404, the script prints:  
       `"Skipping checksum validation as the sha for the release could not be found, no action needed."`  
       and **does not** perform checksum verification.
    7. If the file is found, it downloads the checksum file and calls the `check_sha` function.  
    8. Finally, the tarball is extracted and the appropriate binary is moved into the local `bin/` directory.
    9. **Key Issue:** The conditional skip when the checksum file is missing (HTTP 404) is what attackers can exploit by forcing such a condition, thereby bypassing checksum integrity checks.

  - **Security Test Case:**  
    1. **Set Up a Controlled Testing Environment:**  
       - Configure a local proxy or use a network interception tool (e.g. MITM proxy) to simulate a man‑in-the-middle scenario.
    2. **Simulate Checksum File Absence:**  
       - Intercept the HTTP request for `https://infracost.io/downloads/latest/infracost-$bin_target.tar.gz.sha256` and force it to return an HTTP status code of 404.
    3. **Substitute the Tarball:**  
       - At the same time, intercept and replace the legitimate tarball (`infracost-$bin_target.tar.gz`) with a malicious tarball containing a binary that, for example, prints a distinct message or executes a controlled payload.
    4. **Run the Script:**  
       - Execute the `download.sh` script in the test environment.
    5. **Observe the Output:**  
       - Verify that the script logs “Skipping checksum validation…” indicating that the checksum was not validated.
       - Check that the tarball is extracted and placed into the `bin/` directory.
    6. **Test Executed Binary:**  
       - Run the installed binary to confirm that it reflects the malicious changes (e.g., a benign payload that demonstrates arbitrary command execution, like printing “Malicious binary executed”).
    7. **Conclude the Test:**  
       - Document that bypassing the checksum validation allowed the malicious binary to be installed and executed, proving the vulnerability.