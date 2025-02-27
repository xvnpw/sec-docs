# Vulnerability List

- Vulnerability Name: Insecure Download of JDT Language Server Snapshot over HTTP
- Description: The gulp build script `gulpfile.js` downloads the JDT Language Server snapshot from `http://download.eclipse.org/jdtls/snapshots/jdt-language-server-latest.tar.gz` using HTTP. This insecure protocol is susceptible to Man-in-the-Middle (MITM) attacks. An attacker could intercept the HTTP request and replace the legitimate JDT Language Server snapshot with a malicious one.
- Impact: If a malicious JDT Language Server snapshot is downloaded and used by the VSCode extension, it could lead to Remote Code Execution (RCE) on the user's machine. The attacker could compromise the user's workspace, steal sensitive information, or perform other malicious actions with the privileges of the VSCode user.
- Vulnerability Rank: Critical
- Currently Implemented Mitigations: None. The build script directly uses `http://` for downloading the snapshot.
- Missing Mitigations:
    - Use HTTPS instead of HTTP for downloading the JDT Language Server snapshot. The download URL should be changed to `https://download.eclipse.org/jdtls/snapshots/jdt-language-server-latest.tar.gz`.
    - Implement integrity checks (e.g., checksum verification) for the downloaded JDT Language Server snapshot to ensure that it has not been tampered with during transit.
- Preconditions:
    - The developer or build process executes the gulp task `download_server` or `build_or_download`.
    - The network connection is susceptible to a MITM attack.
- Source Code Analysis:
    - File: `/code/gulpfile.js`
    - ```javascript
      const JDT_LS_SNAPSHOT_URL = "http://download.eclipse.org/jdtls/snapshots/jdt-language-server-latest.tar.gz"

      function download_server_fn(){
          fse.removeSync('./server');
          download(JDT_LS_SNAPSHOT_URL) // Vulnerable HTTP download
              .pipe(decompress())
              .pipe(gulp.dest('./server'));
      }
      ```
    - The `download_server_fn` function in `gulpfile.js` uses `JDT_LS_SNAPSHOT_URL` to download the JDT Language Server snapshot. `JDT_LS_SNAPSHOT_URL` is defined using `http://`, which initiates an insecure HTTP connection.
- Security Test Case:
    1. Set up a MITM proxy (e.g., mitmproxy) to intercept HTTP traffic.
    2. Modify the proxy to intercept requests to `download.eclipse.org/jdtls/snapshots/jdt-language-server-latest.tar.gz`.
    3. Configure the proxy to return a malicious archive file instead of the legitimate JDT Language Server snapshot. This malicious archive should contain a modified JDT Language Server that, for example, executes a simple command like `touch /tmp/pwned` upon startup.
    4. Run the gulp task `download_server` or `build_or_download`.
    5. Observe if the malicious archive is downloaded and extracted by checking the proxy logs.
    6. Start the VSCode Java extension in a test workspace. This should trigger the execution of the downloaded JDT Language Server.
    7. Check if the command injected in the malicious JDT Language Server was executed (e.g., check if the `/tmp/pwned` file exists). If the file exists, it confirms successful RCE due to the insecure HTTP download.