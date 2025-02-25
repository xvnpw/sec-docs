- **Vulnerability Name:** Arbitrary Filesystem Exposure via Malicious tsconfig “baseUrl” Setting
  - **Description:**  
    An attacker can craft a repository with a tsconfig.json file that deliberately sets the “compilerOptions.baseUrl” to an unsafe value—for example, using the system root directory (e.g. “/”). When a user opens such a repository in Visual Studio Code with Path Intellisense installed, the extension will use that unsanitized “baseUrl” value to provide autocompletion suggestions. As a result, file suggestions may include directories and files from the entire disk rather than being limited to the workspace.
    - Step 1: The attacker creates a repository containing a tsconfig.json with a malicious “baseUrl”, for instance:  
      ```json
      {
        "compilerOptions": {
          "baseUrl": "/"
        }
      }
      ```
    - Step 2: A user (the victim) opens this repository in Visual Studio Code.
    - Step 3: The extension reads the tsconfig.json, accepts “/” as the base, and begins providing path suggestions.
    - Step 4: The victim, when triggering autocompletion (e.g., typing an import statement), is presented with file and directory names from the entire filesystem.
  - **Impact:**  
    Sensitive system directories and file names could be exposed to the user. This information disclosure might assist an attacker in further targeted attacks or be used to gather intelligence on the victim’s system layout and configuration.
  - **Vulnerability Rank:** High
  - **Currently Implemented Mitigations:**  
    The documentation notes that the behavior based on tsconfig’s “baseUrl” can be disabled by manually setting `"path-intellisense.ignoreTsConfigBaseUrl": true` in user settings. However, there is no built‑in enforcement or default safe behavior within the extension code.
  - **Missing Mitigations:**  
    • No input validation or sanitization is applied to the “baseUrl” value from tsconfig.json.  
    • The extension should restrict the accepted “baseUrl” to directories within the workspace or apply safe defaults if an out‑of‑bound value is detected.
  - **Preconditions:**  
    • The victim must open a repository containing a malicious tsconfig.json with “compilerOptions.baseUrl” set to an arbitrary directory (e.g. “/”).  
    • The victim has not preemptively disabled the tsconfig-based mapping by enabling the ignore flag.
  - **Source Code Analysis:**  
    Although the actual implementation code is not shown, the README explains that the extension “uses the ts.config.compilerOptions.baseUrl as a mapping.” There is no indication that the extension checks whether the provided baseUrl is confined within the workspace. Thus, a value such as “/” would be accepted as is, resulting in the resolution of absolute paths to the disk’s root directory. The CHANGELOG history does not mention any sanitization fixes for this behavior.
  - **Security Test Case:**  
    1. Create a test repository containing a tsconfig.json with the following content:
       ```json
       {
         "compilerOptions": {
           "baseUrl": "/"
         }
       }
       ```
    2. Open the repository in Visual Studio Code with the Path Intellisense extension installed.
    3. In a source file, start writing an import statement (e.g., type `import x from "`).
    4. Observe the auto-completion suggestions.  
    5. Confirm that the suggestions include file paths outside the workspace (for example, directories like `/etc`, `/bin`, etc.), thus verifying the vulnerability.

- **Vulnerability Name:** Arbitrary Filesystem Exposure via Malicious tsconfig “paths” Mapping
  - **Description:**  
    Path Intellisense also utilizes the “compilerOptions.paths” defined in a repository’s tsconfig.json to provide custom mappings for file autocompletion. An attacker can supply a tsconfig.json with a mapping that points to a sensitive directory—for example, mapping a key to “/etc/”. When a user opens such a repository, the extension will resolve the mapping and present file suggestions from that sensitive directory.
    - Step 1: The attacker creates a repository with a tsconfig.json similar to:
      ```json
      {
        "compilerOptions": {
          "paths": {
            "secret/*": ["/etc/"]
          }
        }
      }
      ```
    - Step 2: A victim opens the repository in Visual Studio Code.
    - Step 3: The extension reads the “paths” mapping without validating its scope.
    - Step 4: Upon typing an import statement starting with “secret/”, the extension triggers suggestions from the `/etc/` directory.
  - **Impact:**  
    The extension may unintentionally disclose the contents and structure of sensitive system directories (for example, configuration files in `/etc`). This information can be used by an attacker to map out the system’s configuration and possibly identify further vulnerabilities.
  - **Vulnerability Rank:** High
  - **Currently Implemented Mitigations:**  
    There are no built‑in checks described in the documentation to limit the directories that can be referenced in the “paths” mapping. The feature works as described without additional sanitization.
  - **Missing Mitigations:**  
    • The extension should implement input validation on the tsconfig “paths” values to ensure that they resolve only to locations within the current workspace.  
    • A whitelist of acceptable directories or a boundary check against the workspace root is missing.
  - **Preconditions:**  
    • The user must open a repository containing a deliberately malicious tsconfig.json in which “compilerOptions.paths” includes mappings that point to directories outside the intended project workspace (e.g., “/etc/”).  
    • The user has not overridden or corrected the mapping manually.
  - **Source Code Analysis:**  
    The README explicitly states that “Pathintellisense uses the ts.config.compilerOptions.paths as a mapping” and provides examples that allow absolute paths. There is no mention that these mapping values are verified against the workspace boundaries. This means a malicious value (such as mapping “secret/*” to “/etc/”) would be accepted and used directly by the extension to resolve file suggestions.
  - **Security Test Case:**  
    1. Create a test repository containing a tsconfig.json with the following content:
       ```json
       {
         "compilerOptions": {
           "paths": {
             "secret/*": ["/etc/"]
           }
         }
       }
       ```
    2. Open the repository in Visual Studio Code with the Path Intellisense extension installed.
    3. In a source file, type the beginning of an import statement such as `import config from "secret/`.
    4. Check the auto-completion suggestions that appear.
    5. Confirm that the suggestions include file names from the `/etc/` directory, thus verifying that the sensitive directory content is being exposed.