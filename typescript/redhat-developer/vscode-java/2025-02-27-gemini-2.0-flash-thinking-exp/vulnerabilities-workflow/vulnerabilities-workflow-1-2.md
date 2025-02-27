- **Vulnerability Name:** Insecure HTTP Download of JDT Language Server Binary in Build and Test Workflows  
  - **Description:**  
    The extension downloads a critical JDT Language Server binary over an unencrypted (HTTP) connection when performing certain build or continuous integration (CI) tasks. An attacker who can intercept network traffic on an insecure or compromised network may substitute the genuine binary with a malicious payload.  
    *Triggering Steps:*  
    - The attacker positions themselves where network traffic is unencrypted (for example, a public Wi‑Fi hotspot or via DNS spoofing).  
    - A developer’s machine or CI environment initiates a download over an HTTP URL (e.g. in gulp tasks or build scripts).  
    - The attacker intercepts the HTTP request and replaces the legitimate binary with one embedded with malicious code.  
    - When the extension loads the binary, it executes the injected payload, allowing arbitrary code execution.
  
  - **Impact:**  
    - An attacker who successfully intercepts and tampers with the binary can execute arbitrary code with the privileges of the extension host.  
    - This may lead to unauthorized operations, data exfiltration, or lateral movement within connected systems.
  
  - **Vulnerability Rank:** **High**
  
  - **Currently Implemented Mitigations:**  
    - In parts of the build and release pipelines (outside of certain gulp tasks and CI workflows) the project enforces HTTPS URLs. However, in at least two key locations responsible for downloading the JDT Language Server binary, HTTP is still used.
  
  - **Missing Mitigations:**  
    - Replace all HTTP endpoints with secure HTTPS endpoints (e.g. use `https://download.eclipse.org/...` instead of `http://download.eclipse.org/...`).  
    - Add integrity checking (through cryptographic hash verification or digital signatures) to ensure that the binary has not been tampered with during download.
  
  - **Preconditions:**  
    - The build environment (either on a developer’s machine or CI runner) must be connected to a network where HTTP traffic is unencrypted or compromised.  
    - The attacker must have the ability to intercept and modify HTTP traffic targeting the download URL.
  
  - **Source Code Analysis:**  
    - In the build and test-related scripts (for example, in gulp tasks or similar workflow definitions), the URL used for downloading the JDT Language Server binary is specified using the HTTP scheme instead of HTTPS.  
    - There is no mechanism (such as checksum or digital signature verification) that validates the integrity of the downloaded binary after the HTTP transfer.
  
  - **Security Test Case:**  
    1. **Test Setup:**  
       - Create a controlled test environment where the network path can be intercepted (using tools such as mitmproxy or a configured HTTP proxy).  
       - Ensure that the environment is set up so that HTTP traffic (e.g. requests to `http://download.eclipse.org/jdtls/...`) is routed through the interceptor.
    2. **Execution:**  
       - Trigger the binary download by running the appropriate gulp task or CI workflow that initiates the HTTP download.  
       - Use the proxy to intercept the request and substitute the genuine binary with a maliciously modified payload.
    3. **Verification:**  
       - Confirm that the binary is indeed fetched over an unencrypted (HTTP) connection.  
       - Verify that no integrity check is performed (i.e. the malicious binary passes unnoticed) by observing that the extension later executes the injected binary. This demonstrates that an attacker on an insecure network could replace the binary, leading to potential arbitrary code execution.