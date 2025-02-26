### Combined Vulnerability List

- **Vulnerability Name:** Command Injection in Icon Generation Script
  **Description:**
  1. An attacker tricks a developer into using a malicious path as the Godot repository path when running the `generate_icons.ts` script.
  2. The developer runs the `generate_icons.ts` script to generate icons for the extension, providing the malicious path as a command-line argument.
  3. The script uses this path as the current working directory for executing Git commands using `child_process.exec`.
  4. Because `child_process.exec` executes commands in a shell, shell commands embedded in the malicious path are executed on the developer's machine. For example, a malicious path like `/tmp/godot_repo; touch PWNED` would execute `touch PWNED`.
  **Impact:** Arbitrary command execution on the developer's machine. This can lead to:
    - Data theft from the developer's system.
    - Installation of malware or backdoors.
    - System compromise and potential lateral movement in the developer's network.
  **Vulnerability Rank:** High
  **Currently Implemented Mitigations:** None
  **Missing Mitigations:**
    - Input validation for the `godotPath` argument in `generate_icons.ts` to ensure it is a valid directory path and does not contain any shell metacharacters or malicious commands.
    - Instead of directly using `child_process.exec` with a potentially user-controlled path, use `child_process.spawn` with explicitly defined arguments for Git commands, avoiding shell execution where possible.
    - Consider using a dedicated Git library for Node.js to further reduce the risk of command injection.
  **Preconditions:**
    - An attacker must trick a developer into running the `generate_icons.ts` script with a malicious path.
    - The developer must have `ts-node` installed and execute the script.
  **Source Code Analysis:**
    - File: `/code/tools/generate_icons.ts`
    - The script retrieves the Godot repository path from command-line arguments using `process.argv[2]` on line 489:
      ```typescript
      const godotPath = process.argv[2];
      ```
    - This `godotPath` is used directly in `child_process.exec` calls without sanitization.
    - The `exec` function (lines 45-48) wraps `child_process.exec`:
      ```typescript
      async function exec(command) {
          const { stdout, stderr } = await _exec(command);
          return stdout;
      }
      ```
    - Git commands are executed using this `exec` function, for example on line 498:
      ```typescript
      const diff = (await exec(git.diff)).trim();
      ```
    - A malicious `godotPath` like `/tmp/pwned; touch PWNED` will cause the script to execute `touch PWNED` due to shell command injection when `child_process.exec` is used.
  **Security Test Case:**
    1. An attacker crafts instructions to trick a developer into running the icon generation script with a malicious path.
    2. The developer opens a terminal, navigates to the project root, and executes:
       ```bash
       npx ts-node ./code/tools/generate_icons.ts "/tmp/pwned; touch /tmp/PWNED"
       ```
    3. After execution, the attacker checks if the file `/tmp/PWNED` is created on the developer's system.
    4. If `/tmp/PWNED` exists, command injection is confirmed.

- **Vulnerability Name:** Out-of-bounds read in Variant Decoder
  **Description:**
    1. An attacker crafts a malicious Godot project that, when debugged, sends a debugger message with a data buffer shorter than 4 bytes to the VSCode extension.
    2. When the extension's `VariantDecoder.get_dataset` function processes this buffer, it attempts to read the buffer length from the first 4 bytes using `buffer.readUInt32LE(0)`.
    3. Because the buffer is shorter than 4 bytes, `buffer.readUInt32LE(0)` reads out of bounds, causing the extension to crash.
  **Impact:** Crash of the VSCode extension during debugging. This leads to a denial of service of the debugging functionality and a degraded user experience.
  **Vulnerability Rank:** High
  **Currently Implemented Mitigations:** None
  **Missing Mitigations:**
    - Implement a check at the beginning of `VariantDecoder.get_dataset` to verify if the input buffer is at least 4 bytes long before attempting to read its length.
    - If the buffer is shorter than 4 bytes, handle it gracefully, such as by logging an error and returning `undefined`, instead of proceeding with the out-of-bounds read.
  **Preconditions:**
    - An attacker provides a malicious Godot project to a user for debugging.
    - The user opens this project in VSCode and starts a debugging session, connecting to the malicious Godot debugger.
  **Source Code Analysis:**
    - File: `/code/src/debugger/godot3/variables/variant_decoder.ts` (and `/code/src/debugger/godot4/variables/variant_decoder.ts`)
    - Function: `get_dataset`
    - Vulnerable code:
      ```typescript
      public get_dataset(buffer: Buffer) {
          const len = buffer.readUInt32LE(0); // Out-of-bounds read if buffer.length < 4
          if (buffer.length != len + 4) {
              return undefined;
          }
          ...
      }
      ```
    - The code directly reads a UInt32 from the beginning of the buffer without checking its size, leading to a potential out-of-bounds read if the buffer is too short.
  **Security Test Case:**
    1. An attacker creates a malicious Godot project designed to send short debugger messages.
    2. A user opens this project in VSCode and starts a debug session.
    3. During debugging, the malicious Godot project sends a crafted debugger message with a buffer of length less than 4 bytes.
    4. The VSCode extension processes this message using `VariantDecoder.get_dataset`.
    5. The extension crashes due to an out-of-bounds read in `buffer.readUInt32LE(0)`.
    6. The attacker observes the VSCode extension crashing, confirming the vulnerability.

- **Vulnerability Name:** Out-of-bounds read in `split_buffers` function
  **Description:**
    1. An attacker crafts a malicious Godot project that, when debugged, sends a debugger message containing a buffer with manipulated length prefixes.
    2. The extension's `split_buffers` function processes this buffer to split it into sub-buffers based on the length prefixes.
    3. By crafting malicious length prefixes, the attacker can cause `split_buffers` to attempt to read lengths or create sub-buffers that extend beyond the boundaries of the main buffer, leading to an out-of-bounds read.
    4. This out-of-bounds read causes the VSCode extension to crash.
  **Impact:** Crash of the VSCode extension during debugging. This results in denial of service of the debugging feature and a negative impact on user experience.
  **Vulnerability Rank:** High
  **Currently Implemented Mitigations:** None
  **Missing Mitigations:**
    - In the `split_buffers` function, before reading each sub-buffer length with `buffer.readUInt32LE(offset)`, validate that `offset + 4` is within the bounds of the buffer.
    - Before creating each sub-buffer using `buffer.subarray(offset, offset + subLength)`, verify that `offset + subLength` does not exceed the buffer's length.
    - If any of these boundary checks fail, handle the malformed buffer gracefully, e.g., by logging an error and stopping the buffer splitting process.
  **Preconditions:**
    - An attacker provides a malicious Godot project to a user for debugging.
    - The user opens this project in VSCode and starts a debugging session, connecting to the malicious Godot debugger.
  **Source Code Analysis:**
    - File: `/code/src/debugger/godot3/helpers.ts` (and `/code/src/debugger/godot4/helpers.ts`)
    - Function: `split_buffers`
    - Vulnerable code:
      ```typescript
      export function split_buffers(buffer: Buffer) {
          let len = buffer.byteLength;
          let offset = 0;
          const buffers: Buffer[] = [];
          while (len > 0) {
              const subLength = buffer.readUInt32LE(offset) + 4; // Potential OOB read
              buffers.push(buffer.subarray(offset, offset + subLength)); // Potential OOB read
              offset += subLength;
              len -= subLength;
          }
          return buffers;
      }
      ```
    - The loop reads sub-buffer lengths and creates sub-buffers without proper boundary checks, which can lead to out-of-bounds reads if the input buffer is maliciously crafted.
  **Security Test Case:**
    1. An attacker creates a malicious Godot project that sends crafted debugger messages with manipulated length prefixes.
    2. A user opens this project in VSCode and starts debugging.
    3. During debugging, the malicious project sends a debugger message with a buffer where length prefixes are designed to cause an out-of-bounds read in `split_buffers`.
    4. The VSCode extension processes the message using `split_buffers`.
    5. The extension crashes due to an out-of-bounds read, either in `readUInt32LE` or `subarray`.
    6. The attacker observes the crash, confirming the vulnerability.

- **Vulnerability Name:** Cross‐Site Scripting (XSS) in Documentation Webview via Unsanitized URI Fragment
  **Description:**
  When a “gddoc” URI is processed, its fragment is embedded without proper escaping into an inline script. An attacker can supply a malicious fragment (for example, using input such as `'); alert('XSS');//`) that escapes the string context and triggers arbitrary JavaScript execution in the webview.
  **Impact:**
  Exploitation can lead to arbitrary script execution in the extension’s documentation webview. This may allow attackers to hijack user sessions, access sensitive data, or launch further attacks in the context of the extension.
  **Vulnerability Rank:** Critical
  **Currently Implemented Mitigations:**
  - The fragment is currently interpolated directly into the JavaScript string without any sanitization.
  **Missing Mitigations:**
  - Escape or validate any data coming from the URI fragment before inserting it into inline scripts.
  - Alternatively, avoid inline code injection by passing the value via secure APIs or using a safe templating system.
  **Preconditions:**
  - The attacker must be able to supply or modify a “gddoc” URI (for example by publishing or distributing a malicious link).
  **Source Code Analysis:**
  - In the documentation builder (e.g., in `/code/src/providers/documentation_builder.ts`), the fragment extracted from the URI is directly concatenated into an inline JavaScript snippet that simply scrolls the document into view. No sanitization is applied, so an input such as
    ```
    '); alert('XSS');//
    ```
    can break out of the intended context.
  **Security Test Case:**
  1. Craft a “gddoc” URI such as:
     ```
     gddoc://path/to/doc#'); alert('XSS');//
     ```
  2. Open this URI in the extension’s documentation webview.
  3. Verify that the injected code executes (for example, an alert box appears), indicating a successful XSS attack.

- **Vulnerability Name:** Command Injection via Unsanitized Debug “additional_options” Field
  **Description:**
  Both the Godot 3 and Godot 4 debugger workflows construct the command used to launch the game process by concatenating various parameters from the debug configuration. In particular, if the configuration supplies an `additional_options` field, its value is appended directly to the shell command without any sanitization. An attacker who can force a launch configuration (for example, by including one in a public workspace or repository) may supply a payload that includes shell metacharacters, thereby injecting and executing arbitrary shell commands.
  **Impact:**
  Successful exploitation may lead to arbitrary shell command execution. This can result in full system compromise, loss of data, or installation of malware.
  **Vulnerability Rank:** Critical
  **Currently Implemented Mitigations:**
  - No filtering or sanitization is performed on the contents of the `additional_options` field.
  **Missing Mitigations:**
  - Validate and sanitize the `additional_options` input to disallow dangerous shell metacharacters.
  - Consider refactoring the command‐building process to pass arguments as an array (thus bypassing the shell) rather than concatenating strings.
  **Preconditions:**
  - The attacker must be able to supply a malicious debug launch configuration (for example, via a malicious repository or workspace file).
  **Source Code Analysis:**
  - In both `/code/src/debugger/godot3/server_controller.ts` and `/code/src/debugger/godot4/server_controller.ts`, the debug command string is built from configuration parameters. When `args.additional_options` is provided, it is added with no encoding or sanitization, so a payload like
    ```
    ; echo INJECTED; #
    ```
    would be appended to the command and executed by the shell.
  **Security Test Case:**
  1. Create a launch configuration (launch.json) that sets `additional_options` to a payload such as:
     ```
     ; echo INJECTED; #
     ```
  2. Launch a debug session using this configuration.
  3. Monitor the system’s terminal or log output for evidence that the injected command (e.g. printing “INJECTED”) was executed.

- **Vulnerability Name:** Directory Traversal / Arbitrary File Read via Unsanitized Resource Paths
  **Description:**
  To convert a “res://” resource path into a local file system URI, the extension removes the “res://” prefix and joins the remainder with the project directory. No normalization or checks are performed on the remaining path, allowing an attacker to include directory traversal sequences (such as `../`). This can cause the resulting path to point to files outside of the project directory.
  **Impact:**
  An attacker may be able to trick the extension into reading arbitrary files (such as sensitive configuration files or system files) located outside the intended directory. This may result in severe information disclosure.
  **Vulnerability Rank:** Critical
  **Currently Implemented Mitigations:**
  - The conversion function (e.g., in `/code/src/utils/project_utils.ts`) simply performs a string manipulation without validating that the final path remains within the project’s boundaries.
  **Missing Mitigations:**
  - Normalize the resultant path and then verify that it falls under the project directory boundary.
  - Reject or appropriately sanitize any resource path containing directory traversal sequences (e.g., `../`).
  **Preconditions:**
  - An attacker must be able to supply or commit a malicious resource path (for example, in a scene or resource file within a public repository).
  **Source Code Analysis:**
  - In the resource path conversion code (in `/code/src/utils/project_utils.ts`), the function strips off “res://” and then uses a simple join with the project directory. Without proper path normalization, a supplied value like
    ```
    res://../../../../etc/passwd
    ```
    will resolve to a location outside the intended directory, allowing unauthorized file access.
  **Security Test Case:**
  1. In a test or controlled malicious repository, include a resource reference with a path such as:
     ```
     res://../secret.txt
     ```
     where “secret.txt” exists outside the project folder.
  2. Trigger functionality that loads or previews the referenced resource.
  3. Confirm that the contents of the file outside the workspace (i.e. “secret.txt”) are read or displayed by the extension.

- **Vulnerability Name:** Unauthenticated Debug Server Socket
  **Description:**
  The extension sets up a debug server by creating a Node.js network socket (using `net.createServer`) and binding it to an address and port as specified in the launch configuration. No authentication or encryption is implemented on this socket. This means that any entity that can access the network interface on which the server is bound may connect and send debug commands that are subsequently interpreted by the extension.
  **Impact:**
  An attacker with network access to the debug server could inject arbitrary debug commands. This could result in manipulation of the debug session (for example, altering breakpoints, stopping or continuing execution, or changing variable states) and may lead to sensitive debug information disclosure or further compromise of the target system.
  **Vulnerability Rank:** Critical
  **Currently Implemented Mitigations:**
  - Neither authentication nor encryption is implemented. The server listens on `args.address` and `args.port` and processes all incoming data directly through `socket.on("data", …)`.
  **Missing Mitigations:**
  - Implement authentication and authorization on the debug server socket to ensure that only trusted/debugging clients can connect.
  - Restrict the binding to localhost (127.0.0.1) when remote debugging is not explicitly required.
  - Optionally, deploy TLS encryption on the communication channel and validate the origin of incoming messages.
  **Preconditions:**
  - The debug server must be bound to an externally accessible network interface (for example, using a misconfigured `args.address` such as `0.0.0.0` instead of `127.0.0.1`).
  - The attacker must have network access to the host machine’s debug port.
  **Source Code Analysis:**
  - In `/code/src/debugger/godot4/server_controller.ts` (and similarly in the Godot 3 controller), the code calls:
    ```ts
    this.server = net.createServer((socket) => { … });
    this.server.listen(args.port, args.address);
    ```
    Once a connection is made, incoming data are processed without verifying the identity or origin of the sender. The absence of any checks means that if this port is exposed beyond localhost, an unauthorized party can send properly formatted debug commands that the extension will obey.
  **Security Test Case:**
  1. Configure a debug launch with its network parameter (args.address) set to a publicly accessible interface (for example, `0.0.0.0`).
  2. From an external system (or another terminal on the same machine if the port is publicly reachable), connect to the specified debug port using a network tool such as netcat (`nc`).
  3. Send a payload that mimics a valid debug command (properly encoded using the extension’s VariantEncoder/Decoder format), for example a “debug_enter” command.
  4. Verify that the debug session processes the injected command—such as by observing altered debugger state, output messages, or breakpoints—thus confirming that the socket accepts unauthenticated input.

- **Vulnerability Name:** Path Traversal in Resource Path Conversion
  **Description:**
    1. The extension uses the `convert_resource_path_to_uri` function to convert resource paths (starting with `res://`) to VS Code `Uri` objects.
    2. This function, located in `/code/src/utils/project_utils.ts`, takes a resource path as input and joins it with the project directory using `vscode.Uri.joinPath`.
    3. The function does not perform any sanitization or validation on the resource path before joining it with the project directory.
    4. An attacker could craft a malicious resource path containing path traversal sequences like `..` to escape the project directory and access files outside of it.
    5. This vulnerability can be triggered in multiple features that use `convert_resource_path_to_uri` and process resource paths from potentially attacker-controlled sources. These features include:
        - **Debugger Error Reporting:** When the Godot engine sends error messages during debugging (e.g., in `handle_error` function in `/code/src/debugger/godot3/server_controller.ts` and `/code/src/debugger/godot4/server_controller.ts`), these messages can contain file paths as part of the debugger protocol. If a malicious project is crafted to trigger errors with malicious resource paths, it can lead to path traversal when the extension converts these paths for display in the debug console or for source links. The vulnerability is triggered when the extension processes the `file` parameter from the debugger `error` command, which originates from `params[4]` in Godot 3 and `params[5]` in Godot 4.
        - **Document Links:** The document link provider (in `/code/src/providers/document_link.ts`) scans files for `res://` paths and creates clickable links in the editor. If a malicious file contains a crafted `res://` path, clicking on the link could trigger path traversal. The vulnerability is triggered when the extension processes the matched `res://` path from the document text in `provideDocumentLinks`.
        - **Hover Previews:** The hover provider (in `/code/src/providers/hover.ts`) scans for `res://` paths in the text and attempts to display previews (e.g., for images or scripts). If a malicious file contains a crafted `res://` path, hovering over it could trigger path traversal. The vulnerability is triggered when the extension processes the matched `res://` path under the mouse cursor in `provideHover`.
    6. For example, a malicious error message from the Godot engine, triggered by a crafted `.gd` script or scene, could contain a resource path like `res://../../../../etc/passwd`. Similarly, a malicious `.gd` or `.tscn` file could directly contain or construct a string like `res://../../../../etc/passwd`. When the extension processes these resource paths in debugger error handling, document links, or hover previews, it could attempt to create a `Uri` for `/etc/passwd`.
  **Impact:**
    - High
    - An attacker could potentially read arbitrary files on the user's system if they can control the resource paths processed by the extension. This can be achieved by:
        - Crafting a malicious Godot project or scene file that, when debugged, causes the Godot engine to send an error message containing a malicious path to the VSCode extension. This is possible by triggering errors in GDScript using functions like `load()` with crafted paths.
        - Crafting a malicious Godot project that includes scene or script files with malicious `res://` paths that are processed by the document link or hover providers when the user opens these files in VSCode. This can be done by embedding malicious `res://` paths directly in strings in `.gd`, `.tscn`, or other text-based project files.
    - In the context of VSCode extension sandbox, the impact might be limited to what the extension can access within the sandbox, but it's still a security risk allowing access to sensitive user data within the sandbox or potentially escaping the sandbox in some environments.
  **Vulnerability Rank:** high
  **Currently Implemented Mitigations:**
    - None. The code directly joins the project directory with the unsanitized resource path in `/code/src/utils/project_utils.ts` and uses it in `/code/src/debugger/godot3/server_controller.ts`, `/code/src/debugger/godot4/server_controller.ts`, `/code/src/providers/document_link.ts`, and `/code/src/providers/hover.ts`.
  **Missing Mitigations:**
    - Input validation and sanitization of the `resPath` in `convert_resource_path_to_uri` function in `/code/src/utils/project_utils.ts`. This should include checks to prevent path traversal sequences like `..`.
    - Path normalization of the `resPath` to remove redundant separators and traversal sequences before joining it with the project directory.
    - Check if the resolved path is still within the project directory or a safe zone after joining and normalizing, before creating a `Uri` in `convert_resource_path_to_uri` function in `/code/src/utils/project_utils.ts`.
    - Apply sanitization or validation within the `handle_error` function in `/code/src/debugger/godot3/server_controller.ts` and `/code/src/debugger/godot4/server_controller.ts` before calling `convert_resource_path_to_uri`. This can be done by validating the `e.file` before passing it to `convert_resource_path_to_uri`.
    - Apply sanitization or validation within the `provideDocumentLinks` function in `/code/src/providers/document_link.ts` before calling `convert_resource_path_to_uri`. This can be done by validating the `match[0]` before passing it to `convert_resource_path_to_uri`.
    - Apply sanitization or validation within the `provideHover` function in `/code/src/providers/hover.ts` before calling `convert_resource_path_to_uri`. This can be done by validating the `link` before passing it to `convert_resource_path_to_uri`.
  **Preconditions:**
    - The user must open a Godot project in VSCode with the Godot Tools extension installed and enabled.
    - For Debugger Trigger: The user must start a debug session for a Godot project and the extension must process an error message from the Godot engine where the attacker can control the file path. This requires the user to run a crafted scene or script that triggers an error with a malicious path.
    - For Document Link Trigger: The user must open a file (e.g., `.gd`, `.tscn`, `.tres`) within a Godot project in VSCode that contains a malicious `res://` path. The attacker needs to provide a malicious project containing such files.
    - For Hover Preview Trigger: The user must open a file (e.g., `.gd`, `.tscn`, `.tres`) within a Godot project in VSCode and hover over a malicious `res://` path. Similar to document links, this requires a malicious project with crafted files.
  **Source Code Analysis:**
    1. Vulnerable Function: `/code/src/utils/project_utils.ts` - `convert_resource_path_to_uri(resPath: string)`
    ```typescript
    export async function convert_resource_path_to_uri(resPath: string): Promise<vscode.Uri | null> {
    	const dir = await get_project_dir();
    	return vscode.Uri.joinPath(vscode.Uri.file(dir), resPath.substring("res://".length));
    }
    ```
    This function directly concatenates the project directory with the resource path without any validation.

    2. Vulnerable Usage 1: `/code/src/debugger/godot3/server_controller.ts` and `/code/src/debugger/godot4/server_controller.ts` - `handle_error(command: Command)`
    ```typescript
    // In godot3/server_controller.ts
    async handle_error(command: Command) {
        ...
        const e = {
            ...
            file: params[4] as string, // e.file is derived from params[4] from debugger protocol in Godot 3
            ...
        };
        const extras = {
            source: { name: (await convert_resource_path_to_uri(e.file)).toString() }, // e.file is passed to convert_resource_path_to_uri
            line: e.line,
        };
        ...
    }

    // In godot4/server_controller.ts
    async handle_error(command: Command) {
        ...
        const e = {
            ...
            file: params[5] as string, // e.file is derived from params[5] from debugger protocol in Godot 4
            ...
        };
        const extras = {
            source: { name: (await convert_resource_path_to_uri(e.file)).toString() }, // e.file is passed to convert_resource_path_to_uri
            line: e.line,
        };
        ...
    }
    ```
    The `handle_error` function in both Godot 3 and 4 debugger controllers receives file paths from the debugger protocol and passes them directly to `convert_resource_path_to_uri` without sanitization. The file path is taken from `params[4]` in Godot 3 and `params[5]` in Godot 4 of the `error` command.

    3. Vulnerable Usage 2: `/code/src/providers/document_link.ts` - `provideDocumentLinks(document: TextDocument, token: CancellationToken)`
    ```typescript
    async provideDocumentLinks(document: TextDocument, token: CancellationToken): Promise<DocumentLink[]> {
        ...
        for (const match of text.matchAll(/res:\/\/([^"'\n]*)/g)) {
            const r = this.create_range(document, match);
            const uri = await convert_resource_path_to_uri(match[0]); // match[0] is passed to convert_resource_path_to_uri
            if (uri instanceof Uri) {
                links.push(new DocumentLink(r, uri));
            }
        }
        ...
    }
    ```
    The `provideDocumentLinks` function extracts `res://` paths from the document text using a regex and passes them directly to `convert_resource_path_to_uri` without sanitization.

    4. Vulnerable Usage 3: `/code/src/providers/hover.ts` - `provideHover(document: TextDocument, position: Position, token: CancellationToken)`
    ```typescript
    async provideHover(document: TextDocument, position: Position, token: CancellationToken): Promise<Hover> {
        ...
        const link = document.getText(document.getWordRangeAtPosition(position, /res:\/\/[^"^']*/));
        if (link.startsWith("res://")) {
            ...
            const uri = await convert_resource_path_to_uri(link); // link is passed to convert_resource_path_to_uri
            ...
        }
        ...
    }
    ```
    The `provideHover` function extracts `res://` paths from the document text under the mouse cursor and passes them directly to `convert_resource_path_to_uri` without sanitization.

    5. Visualization:
       ```
       [Godot Engine Error Message / Malicious Project File] --> resPath (string) --> convert_resource_path_to_uri(resPath) --> vscode.Uri.joinPath(...) --> [Path Traversal]
       ```
  **Security Test Case:**
    1. **Test Case 1: Debugger Error Reporting Path Traversal**
        1. Create a new Godot project (Godot 3 or 4).
        2. Create a new GDScript file, e.g., `error_script.gd`.
        3. In `error_script.gd`, add code to trigger an error with a malicious path in the error message:
           ```gdscript
           func _ready():
               load("res://../../../../../../../../../../../../../../etc/passwd") # Attempt to load a malicious path, triggering an error
           ```
        4. Create a scene and attach `error_script.gd` to a node in the scene.
        5. Save the scene as `error_scene.tscn`.
        6. Open VSCode and open the Godot project created in step 1.
        7. Open the `error_scene.tscn` file in VSCode.
        8. Set a breakpoint in the `convert_resource_path_to_uri` function in `/code/src/utils/project_utils.ts`.
        9. Start debugging the scene in VSCode.
        10. When the Godot engine executes `error_script.gd`, it will attempt to load the malicious resource path, triggering an error.
        11. The Godot Tools extension's debugger will receive the error message from Godot engine and the breakpoint in `convert_resource_path_to_uri` should be hit.
        12. Inspect the `resPath` argument in `convert_resource_path_to_uri`. It should contain the malicious path `res://../../../../../../../../../../../../../../etc/passwd`.
        13. Step over the `vscode.Uri.joinPath` line and inspect the resulting `Uri`. It will point to `/etc/passwd` or a location outside the project directory, confirming the path traversal vulnerability.
        14. Observe if VSCode attempts to access or display content from `/etc/passwd` or another file outside the project, which would further demonstrate the impact (e.g., if the extension attempts to open the file in the editor or log its content).

    2. **Test Case 2: Document Link Path Traversal**
        1. Create a new Godot project (Godot 3 or 4).
        2. Create a new GDScript file, e.g., `malicious_links.gd`.
        3. In `malicious_links.gd`, add a line containing a malicious `res://` path:
           ```gdscript
           var malicious_path = "res://../../../../../../../../../../../../../../etc/passwd" # Malicious resource path
           ```
        4. Save the file as `malicious_links.gd`.
        5. Open VSCode and open the Godot project created in step 1.
        6. Open the `malicious_links.gd` file in VSCode.
        7. Observe the `res://../../../../../../../../../../../../../../etc/passwd` path. It should be recognized as a document link (typically underlined).
        8. Set a breakpoint in the `convert_resource_path_to_uri` function in `/code/src/utils/project_utils.ts`.
        9. Click on the malicious document link in the `malicious_links.gd` file.
        10. The breakpoint in `convert_resource_path_to_uri` should be hit.
        11. Inspect the `resPath` argument in `convert_resource_path_to_uri`. It should contain the malicious path `res://../../../../../../../../../../../../../../etc/passwd`.
        12. Step over the `vscode.Uri.joinPath` line and inspect the resulting `Uri`. It will point to `/etc/passwd` or a location outside the project directory, confirming the path traversal vulnerability.
        13. Observe if VSCode attempts to access or display content from `/etc/passwd` or another file outside the project (e.g., if the extension attempts to open the file in the editor).

    3. **Test Case 3: Hover Preview Path Traversal**
        1. Create a new Godot project (Godot 3 or 4).
        2. Create a new GDScript file, e.g., `malicious_hover.gd`.
        3. In `malicious_hover.gd`, add a line containing a malicious `res://` path:
           ```gdscript
           var malicious_path = "res://../../../../../../../../../../../../../../etc/passwd" # Malicious resource path
           ```
        4. Save the file as `malicious_hover.gd`.
        5. Open VSCode and open the Godot project created in step 1.
        6. Open the `malicious_hover.gd` file in VSCode.
        7. Hover your mouse cursor over the `res://../../../../../../../../../../../../../../etc/passwd` path in the `malicious_hover.gd` file.
        8. Set a breakpoint in the `convert_resource_path_to_uri` function in `/code/src/utils/project_utils.ts`.
        9. Wait for the hover preview to attempt to load.
        10. The breakpoint in `convert_resource_path_to_uri` should be hit.
        11. Inspect the `resPath` argument in `convert_resource_path_to_uri`. It should contain the malicious path `res://../../../../../../../../../../../../../../etc/passwd`.
        12. Step over the `vscode.Uri.joinPath` line and inspect the resulting `Uri`. It will point to `/etc/passwd` or a location outside the project directory, confirming the path traversal vulnerability.
        13. Observe if VSCode attempts to access or display content from `/etc/passwd` or another file outside the project (e.g., if the hover preview tries to display the file content or throws an error related to accessing the file).