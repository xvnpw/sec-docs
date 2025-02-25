- Vulnerability name: Hardcoded Godot download URL in CI script
- Description: The CI script for continuous integration downloads the Godot Engine from a hardcoded URL without integrity checks. An attacker who compromises the download source or performs a man-in-the-middle attack could replace the legitimate Godot binary with a malicious one. This malicious binary would then be used in the CI process to build and test the Godot Tools extension.
- Impact: Compromise of the CI environment. If a malicious Godot binary is injected, it could potentially compromise the built extension, leading to a supply chain attack where users of the extension could be affected. This could allow for arbitrary code execution on developer machines or in user's VSCode environments if the malicious code is embedded in the extension.
- Vulnerability rank: High
- Currently implemented mitigations: None. The download URLs for Godot are hardcoded in the CI script without any integrity checks.
- Missing mitigations:
    - Implement integrity checks for downloaded Godot binaries using checksums or digital signatures. Verify these checksums or signatures against a trusted source before using the binary in the CI process.
    - Use a more robust and secure method for managing dependencies and tools in the CI environment, such as a package manager or a dedicated tool version management system that includes integrity verification.
    - Regularly review and update the download URLs and the source of the Godot binaries to ensure they are still trustworthy and secure.
- Preconditions: None. The vulnerability exists in the CI configuration and is triggered every time the CI workflow is executed.
- Source code analysis:
    - File: `/code/.github/workflows/ci.yml`
    - The CI script contains steps to download Godot Engine for Linux, macOS, and Windows.
    - For example, the Linux step uses the following commands:
        ```yaml
        - name: Install Godot (Ubuntu)
          if: matrix.os == 'ubuntu-latest'
          run: |
            wget https://github.com/godotengine/godot/releases/download/4.3-stable/Godot_v4.3-stable_linux.x86_64.zip
            unzip Godot_v4.3-stable_linux.x86_64.zip
            sudo mv Godot_v4.3-stable_linux.x86_64 /usr/local/bin/godot
            chmod +x /usr/local/bin/godot
        ```
    - Similar hardcoded URLs are used for macOS and Windows.
    - The `wget`, `curl`, and `Invoke-WebRequest` commands download the Godot binaries from `https://github.com/godotengine/godot/releases/download/4.3-stable/`.
    - There is no verification of the downloaded files' integrity (e.g., checksum verification) after downloading.
    - An attacker compromising `github.com`, the `godotengine/godot` repository, or performing a man-in-the-middle attack could replace the legitimate Godot binary hosted at these URLs with a malicious executable.
    - Because the CI script directly executes the downloaded binary (`godot --import ...`, `npm test`), a malicious binary could compromise the CI environment.
- Security test case:
    1. Set up a local testing environment that mimics the GitHub Actions CI environment.
    2. Modify the host file or network configuration to redirect the hardcoded Godot download URLs (e.g., `github.com`) to a local malicious server.
    3. Host a malicious Godot binary on the local malicious server, making it accessible via the redirected URLs.
    4. Run the CI workflow (e.g., by triggering a `push` or `pull_request` in a test repository with the modified `.github/workflows/ci.yml` file).
    5. Observe the CI execution logs to confirm that the CI script attempts to download Godot from the redirected malicious server.
    6. Verify that the malicious Godot binary is downloaded and used in subsequent CI steps.
    7. Further, to confirm the impact, the malicious Godot binary could be designed to execute a benign command (e.g., `touch /tmp/ci_compromised`) upon execution. Check for the execution of this command in the CI environment after the test run to confirm successful injection and execution of the malicious binary.