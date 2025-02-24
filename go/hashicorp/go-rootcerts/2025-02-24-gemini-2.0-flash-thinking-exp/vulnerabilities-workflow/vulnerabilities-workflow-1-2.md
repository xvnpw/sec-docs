- **Vulnerability Name:**  
  Unvalidated HOME Environment Variable Allows Keychain Path Manipulation (Darwin-specific)

- **Description:**  
  On Darwin systems the library “works around” Go’s limitation by retrieving certificates from three keychain files. Two keychain paths are hard‐coded, but the third—the login keychain—is constructed dynamically using the user’s home directory as returned by the third‐party function `homedir.Dir()`. Because this function typically relies on the HOME environment variable without further validation, an attacker who is able to influence or set HOME (for instance, in an insecure containerized deployment or via misconfigured startup scripts) can force the library to use an arbitrary location for the login keychain. If the attacker then arranges for a crafted keychain file (containing attacker‑controlled PEM certificates) to exist at that path, the Darwin‑specific `LoadSystemCAs()` routine will load these malicious certificates. In effect, the TLS certificate pool used to verify remote servers becomes compromised.  
  **Step-by-step triggering scenario:**  
  1. The attacker manages to influence the process’s HOME environment variable (for example, setting HOME to `/tmp/malicious_home` instead of the real user directory).  
  2. When `certKeychains()` is called, it uses the manipulated HOME value to build the login keychain path (e.g. `/tmp/malicious_home/Library/Keychains/login.keychain`) rather than the expected trusted location.  
  3. The attacker arranges for a file to exist at that location containing a PEM‑encoded CA certificate that they control.  
  4. During TLS configuration the call to `LoadSystemCAs()` iterates over the keychain paths and executes  
     ```
     exec.Command("/usr/bin/security", "find-certificate", "-a", "-p", keychain)
     ```
     with the attacker‑controlled login keychain path.  
  5. The output of the external security command (now containing the attacker‑provided certificate) is appended to the certificate pool used in TLS connections.

- **Impact:**  
  An attacker who succeeds in inserting their own CA certificate into the certificate pool can then issue fraudulent certificates for any domain. This enables man‑in‑the-middle attacks on TLS connections (whether outbound or incoming) and thus breaks the trust assumptions of TLS. In short, session confidentiality and data integrity may be fully compromised.

- **Vulnerability Rank:**  
  High (potentially Critical in deployments where the environment is directly controllable by an untrusted party)

- **Currently Implemented Mitigations:**  
  - The library calls the trusted macOS security tool (`/usr/bin/security`) to extract certificates from keychains.  
  - Two of the three keychain paths are hard-coded.  
  However, there is no check or validation on the value returned by `homedir.Dir()`, so no mitigation exists against a malicious HOME value.

- **Missing Mitigations:**  
  - **Validation of the HOME environment variable:** The library should validate that the directory returned by `homedir.Dir()` matches an expected pattern or is read-only by the trusted user.  
  - **Configuration override:** Provide an option for an explicit login keychain path rather than unconditionally deriving it from HOME.  
  - **Sandboxing or path whitelisting:** Before using a keychain file, verify that the file resides in one of the known/trusted directories.

- **Preconditions:**  
  - The system is running Darwin (macOS) so that the Darwin‑specific code path is executed.  
  - The attacker is able to influence the environment under which the application launches (for example, through misconfiguration, insecure container orchestration, or manipulation of startup scripts).  
  - The attacker is able to place a crafted keychain file at the location resulting from the manipulated HOME variable.

- **Source Code Analysis:**  
  - In **`/code/rootcerts_darwin.go`** the function `certKeychains()` builds a list of keychain paths:
    - The first two items are hard-coded:
      ```go
      keychains := []string{
         "/System/Library/Keychains/SystemRootCertificates.keychain",
         "/Library/Keychains/System.keychain",
      }
      ```
    - Then, it calls:
      ```go
      home, err := homedir.Dir()
      if err == nil {
         loginKeychain := path.Join(home, "Library", "Keychains", "login.keychain")
         keychains = append(keychains, loginKeychain)
      }
      ```
      Since `homedir.Dir()` typically returns the value of the HOME environment variable without further checks, a manipulated HOME value will yield an unexpected login keychain path.
  - In **`LoadSystemCAs()`**, the code iterates over the keychain paths and for each calls:
    ```go
    cmd := exec.Command("/usr/bin/security", "find-certificate", "-a", "-p", keychain)
    data, err := cmd.Output()
    ```
    The output (which will now reflect the certificates contained in the attacker‑controlled keychain file) is appended to the TLS certificate pool.
  - No sanitization or validation is performed on the keychain path derived from HOME; therefore, if an attacker controls HOME and arranges for a malicious keychain file, the output of the security command is attacker‑controlled.

- **Security Test Case:**  
  **Test Objective:** Verify that manipulating the HOME environment variable on Darwin causes the login keychain path to be derived from the attacker‑controlled value and that a crafted keychain file can influence the loaded certificate pool.  
  **Steps:**  
  1. **Setup:**  
     - Run the test on a Darwin (macOS) system or within an environment that simulates the Darwin‑specific code path.  
     - Set the HOME environment variable to a temporary directory (e.g. `/tmp/malicious_home`) before launching the test.
  2. **Prepare the malicious keychain:**  
     - Create the directory structure: `/tmp/malicious_home/Library/Keychains/`  
     - Place a crafted keychain file named `login.keychain` in that directory. This file should contain a PEM‑encoded certificate that does not belong to any trusted set (for example, a self‑signed certificate with a known fingerprint).
  3. **Run LoadSystemCAs():**  
     - Invoke the `LoadSystemCAs()` function.
  4. **Validation:**  
     - Inspect the returned certificate pool and verify that it includes the certificate from the malicious keychain (e.g. by checking the SHA‑256 fingerprint of the certificate against the known value inserted in the crafted file).
     - Optionally, repeat the test with HOME set to a trusted directory and show that the malicious certificate is not loaded.
  5. **Expected Result:**  
     - When HOME is manipulated, the certificate pool returned from `LoadSystemCAs()` includes certificates from the attacker‑controlled keychain file, demonstrating that the keychain path is derived directly from an unvalidated HOME variable.