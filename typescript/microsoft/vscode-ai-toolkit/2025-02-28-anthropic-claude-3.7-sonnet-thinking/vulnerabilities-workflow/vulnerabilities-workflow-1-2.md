# Vulnerabilities in VSCode AI Toolkit Extension

## Malicious Repository Command Injection via Configuration Files

- **Vulnerability Name:**  
  Malicious Repository Command Injection via Configuration Files

- **Description:**  
  1. **Repository Loading & Command Execution:**  
     The AI Toolkit extension lets users load project templates (from GitHub or local repositories) that include configuration files (for example, infra/finetuning.config.json or infra/inference.config.json). These files contain an array of shell commands (such as invoking a fine-tuning script via `python finetuning/invoke_olive.py && ...`) that the extension automatically executes (often in a WSL shell) to set up the developer's environment.
  2. **Attacker Manipulation:**  
     An attacker who controls a malicious repository (or submits a manipulated project template) can alter these configuration files. By inserting arbitrary or additional shell commands into, for example, the "COMMANDS" array, the attacker can cause the extension to execute unintended commands.
  3. **Execution Flow:**  
     When a victim loads this manipulated repository via the extension, the following occurs:  
       - The extension parses the configuration file without strict validation.  
       - It extracts the command strings, concatenates them, and passes them to a shell (e.g., within WSL).  
       - Any injected commands (such as file‑system modifications, payload download commands, or worse) are executed immediately.
  4. **Result:**  
     This chain of events provides a path for remote code execution (RCE) and command injection initiated purely by delivering a specially modified repository.

- **Impact:**  
  An attacker can achieve arbitrary code execution on the victim's system. This could lead to:  
  - Unauthorized file creation, deletion, or modification  
  - Installation of malware or backdoors  
  - Data exfiltration or corruption  
  - Complete compromise of the development environment

- **Vulnerability Rank:**  
  Critical

- **Currently Implemented Mitigations:**  
  - There is no indication of robust input validation or sanitization in the project documentation regarding the processing of configuration files (e.g., the JSON files containing command arrays).  
  - The extension appears to trust repository content when loading commands without a whitelist or secure execution context.

- **Missing Mitigations:**  
  - **Input Validation & Sanitization:** The system needs to validate and sanitize all content loaded from external repositories before any part of it is interpreted or executed as commands.  
  - **Secure Command Execution:** Implement an execution gateway that uses a strict whitelist of allowed command patterns or, ideally, requires manual review/confirmation of commands extracted from a repository.  
  - **Source Trust Verification:** Enforce that only repositories from trusted sources (or signed templates) can be used for automatic command execution.

- **Preconditions:**  
  - The victim loads a project repository provided by an external (and potentially hostile) source using the AI Toolkit extension.  
  - The extension reads and directly executes configuration files (e.g., JSON files with a "COMMANDS" array) in a shell environment (such as WSL) without proper validation.  
  - The victim's system is configured to allow such shell command execution and is running with sufficient privileges.

- **Source Code Analysis:**  
  1. **Configuration Parsing:**  
     Although no explicit code is provided in these files, the documentation and project structure indicate that files like `infra/finetuning.config.json` are read to obtain a list of commands. For example, the JSON snippet includes a `"COMMANDS"` array containing multiple shell commands.
  2. **Command Execution Flow:**  
     - The extension likely parses these JSON files and concatenates the commands for execution.  
     - There is no evidence (in the provided documentation) of using secure APIs (or sanitization routines) before passing these commands to a shell.
  3. **Potential Injection Point:**  
     - A manipulated repository could replace a benign command (such as installing dependencies) with an injected command (e.g., `touch /tmp/hacked_by_malicious_repo` or a more harmful payload).  
     - Visualization of the flow:  
       - **Step 1:** User selects a repository →  
       - **Step 2:** Extension reads configuration file and extracts commands →  
       - **Step 3:** The raw command string (now containing injected payload) is executed in WSL →  
       - **Step 4:** Malicious code is immediately executed in the victim's environment.
  4. **Lack of Mitigation in Code:**  
     Since the project documentation and samples do not mention any validation or sanitization when processing these configuration files, the attack surface is open for injection if a manipulated repository is provided.

- **Security Test Case:**  
  1. **Setup:**  
     - Create a test repository that mimics a valid project template for AI Toolkit, including a configuration file (e.g., `infra/finetuning.config.json`).
     - In the configuration file, include a `"COMMANDS"` array with a normal command (for example, `python finetuning/invoke_olive.py`) but inject an additional malicious command such as:  
       ```json
       "COMMANDS": [
         "python finetuning/invoke_olive.py",
         "touch /tmp/hacked_by_malicious_repo"
       ]
       ```
  2. **Execution via Extension:**  
     - Using a controlled test environment (with WSL enabled), load this manipulated repository with the AI Toolkit extension.
     - Allow the extension to process the repository and kick off the project generation steps.
  3. **Observation:**  
     - Check if the malicious command was executed by verifying the presence of the file `/tmp/hacked_by_malicious_repo` on the system.
     - Review the extension's output logs for evidence that the commands were executed as provided.
  4. **Validation:**  
     - If the file is created or if other injected payload actions are observed, it confirms that the extension does not validate or sanitize command strings from loaded repository content—demonstrating the vulnerability.