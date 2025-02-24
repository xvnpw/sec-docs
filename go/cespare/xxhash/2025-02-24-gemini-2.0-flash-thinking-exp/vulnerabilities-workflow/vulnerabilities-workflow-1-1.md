### Vulnerability List

- Vulnerability Name: Path Traversal in xxhsum command-line utility
- Description: The `xxhsum` command-line utility is vulnerable to path traversal. It directly uses user-provided file paths from command-line arguments with `os.Open()` without any validation or sanitization. This allows an attacker to specify paths like `../../sensitive_file` to access files outside the intended directory.
- Impact: Information Disclosure. An attacker can read the content of arbitrary files on the system that the `xxhsum` utility has permissions to access. This could include sensitive configuration files, application data, or other confidential information.
- Vulnerability Rank: High
- Currently Implemented Mitigations: None. There is no input validation or sanitization of file paths in the `xxhsum` utility.
- Missing Mitigations: Input validation and sanitization for file paths provided as command-line arguments. The application should validate that the provided paths are within the expected directories or sanitize the paths to prevent traversal attempts. For example, using functions like `filepath.Clean()` to resolve path traversals or explicitly checking if the path is within an allowed base directory.
- Preconditions:
    - The attacker must be able to execute the compiled `xxhsum` binary.
    - The `xxhsum` binary must have sufficient permissions to read the target files that the attacker wants to access via path traversal.
- Source Code Analysis:
    ```go
    // File: /code/xxhsum/xxhsum.go
    package main

    import (
    	"fmt"
    	"io"
    	"os"

    	"github.com/cespare/xxhash/v2"
    )

    func main() {
    	// ... (help message and stdin handling) ...
    	for _, path := range os.Args[1:] { // Vulnerable code: Iterating through user provided paths
    		f, err := os.Open(path) // Vulnerability: Directly opening user provided path without validation
    		if err != nil {
    			fmt.Fprintln(os.Stderr, err)
    			continue
    		}
    		printHash(f, path)
    		f.Close()
    	}
    }
    ```
    The `main` function in `xxhsum.go` iterates through the command-line arguments starting from the second argument (`os.Args[1:]`). Each argument is treated as a file path and directly passed to `os.Open()`.  The `os.Open()` function opens the file at the given path without any checks to prevent directory traversal. This allows an attacker to provide paths containing `..` to navigate up the directory structure and access files outside the intended working directory of the `xxhsum` utility.

- Security Test Case:
    1. Compile the `xxhsum` utility:
       ```bash
       go build ./xxhsum/xxhsum.go
       ```
    2. Run the compiled binary `xxhsum` with a path traversal payload to access the `/etc/passwd` file (or any other accessible sensitive file):
       ```bash
       ./xxhsum ../../../../../etc/passwd
       ```
    3. Observe the output. The command should execute without errors and print the xxhash of the `/etc/passwd` file along with the provided path:
       ```text
       <xxhash>  ../../../../../etc/passwd
       ```
       If you can successfully execute the command and observe an output similar to the above, it confirms that the path traversal vulnerability exists. The `<xxhash>` will be the calculated xxhash of the content of `/etc/passwd`.