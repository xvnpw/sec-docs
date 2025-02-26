### Vulnerability List:

- **Vulnerability Name:**洩露使用者 Home Directory Hash (Home Directory Hash Disclosure)
- **Description:**
    1. The Intelephense extension calculates a SHA256 hash of the user's home directory path.
    2. This hash, along with the licence key, is sent in a POST request to `intelephense.com/activate` during licence key activation.
    3. An attacker monitoring network traffic or intercepting the HTTPS request could potentially obtain this hash.
- **Impact:**
    - **Privacy Violation:** Disclosure of a hash derived from the user's home directory, which could be considered personal and sensitive information.
    - **Potential Information Leakage:** While the hash itself is not the full home directory path, it might reveal information about the user's operating system and username if predictable patterns exist in home directory paths. This information could be used in social engineering or targeted attacks.
    - **Future Attack Vector:** If combined with other vulnerabilities or weaknesses in the Intelephense activation process or backend systems, this hash could potentially be used as part of a more complex attack.
- **Vulnerability Rank:** High
- **Currently Implemented Mitigations:**
    - HTTPS is used for communication, encrypting the transmission of the hash and licence key in transit.
    - The home directory is hashed using SHA256, making it computationally infeasible to reverse directly to the original path.
- **Missing Mitigations:**
    - **Eliminate Home Directory Hash Transmission:** The most effective mitigation is to avoid transmitting any hash derived from the user's home directory. The licence activation process should be redesigned to not require this information.
    - **Anonymize Machine Identification:** If machine identification is necessary for licence management, use a less sensitive and more anonymized method than hashing the home directory. Consider using a randomly generated, unique identifier stored locally.
    - **Transparency and User Consent:**  Clearly document the data collected during licence activation, including the machine identifier, in the extension's privacy policy and obtain explicit user consent before transmitting any potentially sensitive information.
- **Preconditions:**
    - The user must attempt to activate a licence key within the Intelephense extension.
    - An attacker must be in a position to monitor the network traffic between the user's machine and `intelephense.com` or intercept the HTTPS request.
- **Source Code Analysis:**
    - **File:** `/code/src/extension.ts`
    - **Function:** `activateKey(context: ExtensionContext, licenceKey: string)`

    ```typescript
    function activateKey(context: ExtensionContext, licenceKey: string): Promise<void> {

        let postData = querystring.stringify({
            machineId: createHash('sha256').update(os.homedir(), 'utf8').digest('hex'), // Vulnerable line: Hashing and using homedir
            licenceKey: licenceKey
        });

        let options: https.RequestOptions = {
            hostname: 'intelephense.com',
            port: 443,
            path: '/activate',
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded',
                'Content-Length': postData.length
            }
        };

        return new Promise((resolve, reject) => {
            // ... (HTTPS request logic) ...
        });
    }
    ```
    - **Explanation:**
        1. The `activateKey` function is responsible for activating the Intelephense licence.
        2. Inside this function, `createHash('sha256').update(os.homedir(), 'utf8').digest('hex')` calculates a SHA256 hash of the user's home directory path obtained using `os.homedir()`.
        3. This hash is assigned to the `machineId` parameter in the `postData` object.
        4. The `postData`, including the `machineId` and `licenceKey`, is then sent as the body of a POST request to `intelephense.com/activate` over HTTPS.
        5. An attacker intercepting this request could extract the `machineId`, which is the SHA256 hash of the user's home directory.

- **Security Test Case:**
    1. **Precondition:** Set up a network traffic monitoring tool (e.g., Wireshark, tcpdump) on the attacker's machine to capture network traffic.
    2. **Action:** As a user, open Visual Studio Code with the Intelephense extension installed.
    3. **Action:** Attempt to activate an Intelephense licence by executing the "Intelephense: Enter licence key" command and entering a valid or invalid licence key.
    4. **Action:** Observe the network traffic captured by the monitoring tool.
    5. **Verification:** Look for an HTTPS POST request to `intelephense.com/activate`.
    6. **Verification:** Inspect the body of the POST request. It should contain a parameter named `machineId` which holds a 64-character hexadecimal string. This string is the SHA256 hash of the user's home directory.