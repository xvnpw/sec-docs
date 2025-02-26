### Vulnerability List

- Vulnerability Name: Path Traversal in Resource Path Conversion

- Description:
    1. The extension uses the `convert_resource_path_to_uri` function to convert resource paths (starting with `res://`) to VS Code `Uri` objects.
    2. This function, located in `/code/src/utils/project_utils.ts`, takes a resource path as input and joins it with the project directory using `vscode.Uri.joinPath`.
    3. The function does not perform any sanitization or validation on the resource path before joining it with the project directory.
    4. An attacker could craft a malicious resource path containing path traversal sequences like `..` to escape the project directory and access files outside of it.
    5. This vulnerability can be triggered in multiple features that use `convert_resource_path_to_uri` and process resource paths from potentially attacker-controlled sources. These features include:
        - **Debugger Error Reporting:** When the Godot engine sends error messages during debugging (e.g., in `handle_error` function in `/code/src/debugger/godot3/server_controller.ts` and `/code/src/debugger/godot4/server_controller.ts`), these messages can contain file paths as part of the debugger protocol. If a malicious project is crafted to trigger errors with malicious resource paths, it can lead to path traversal when the extension converts these paths for display in the debug console or for source links. The vulnerability is triggered when the extension processes the `file` parameter from the debugger `error` command, which originates from `params[4]` in Godot 3 and `params[5]` in Godot 4.
        - **Document Links:** The document link provider (in `/code/src/providers/document_link.ts`) scans files for `res://` paths and creates clickable links in the editor. If a malicious file contains a crafted `res://` path, clicking on the link could trigger path traversal. The vulnerability is triggered when the extension processes the matched `res://` path from the document text in `provideDocumentLinks`.
        - **Hover Previews:** The hover provider (in `/code/src/providers/hover.ts`) scans for `res://` paths in the text and attempts to display previews (e.g., for images or scripts). If a malicious file contains a crafted `res://` path, hovering over it could trigger path traversal. The vulnerability is triggered when the extension processes the matched `res://` path under the mouse cursor in `provideHover`.
    6. For example, a malicious error message from the Godot engine, triggered by a crafted `.gd` script or scene, could contain a resource path like `res://../../../../etc/passwd`. Similarly, a malicious `.gd` or `.tscn` file could directly contain or construct a string like `res://../../../../etc/passwd`. When the extension processes these resource paths in debugger error handling, document links, or hover previews, it could attempt to create a `Uri` for `/etc/passwd`.

- Impact:
    - High
    - An attacker could potentially read arbitrary files on the user's system if they can control the resource paths processed by the extension. This can be achieved by:
        - Crafting a malicious Godot project or scene file that, when debugged, causes the Godot engine to send an error message containing a malicious path to the VSCode extension. This is possible by triggering errors in GDScript using functions like `load()` with crafted paths.
        - Crafting a malicious Godot project that includes scene or script files with malicious `res://` paths that are processed by the document link or hover providers when the user opens these files in VSCode. This can be done by embedding malicious `res://` paths directly in strings in `.gd`, `.tscn`, or other text-based project files.
    - In the context of VSCode extension sandbox, the impact might be limited to what the extension can access within the sandbox, but it's still a security risk allowing access to sensitive user data within the sandbox or potentially escaping the sandbox in some environments.

- Vulnerability Rank: high

- Currently Implemented Mitigations:
    - None. The code directly joins the project directory with the unsanitized resource path in `/code/src/utils/project_utils.ts` and uses it in `/code/src/debugger/godot3/server_controller.ts`, `/code/src/debugger/godot4/server_controller.ts`, `/code/src/providers/document_link.ts`, and `/code/src/providers/hover.ts`.

- Missing Mitigations:
    - Input validation and sanitization of the `resPath` in `convert_resource_path_to_uri` function in `/code/src/utils/project_utils.ts`. This should include checks to prevent path traversal sequences like `..`.
    - Path normalization of the `resPath` to remove redundant separators and traversal sequences before joining it with the project directory.
    - Check if the resolved path is still within the project directory or a safe zone after joining and normalizing, before creating a `Uri` in `convert_resource_path_to_uri` function in `/code/src/utils/project_utils.ts`.
    - Apply sanitization or validation within the `handle_error` function in `/code/src/debugger/godot3/server_controller.ts` and `/code/src/debugger/godot4/server_controller.ts` before calling `convert_resource_path_to_uri`. This can be done by validating the `e.file` before passing it to `convert_resource_path_to_uri`.
    - Apply sanitization or validation within the `provideDocumentLinks` function in `/code/src/providers/document_link.ts` before calling `convert_resource_path_to_uri`. This can be done by validating the `match[0]` before passing it to `convert_resource_path_to_uri`.
    - Apply sanitization or validation within the `provideHover` function in `/code/src/providers/hover.ts` before calling `convert_resource_path_to_uri`. This can be done by validating the `link` before passing it to `convert_resource_path_to_uri`.

- Preconditions:
    - The user must open a Godot project in VSCode with the Godot Tools extension installed and enabled.
    - For Debugger Trigger: The user must start a debug session for a Godot project and the extension must process an error message from the Godot engine where the attacker can control the file path. This requires the user to run a crafted scene or script that triggers an error with a malicious path.
    - For Document Link Trigger: The user must open a file (e.g., `.gd`, `.tscn`, `.tres`) within a Godot project in VSCode that contains a malicious `res://` path. The attacker needs to provide a malicious project containing such files.
    - For Hover Preview Trigger: The user must open a file (e.g., `.gd`, `.tscn`, `.tres`) within a Godot project in VSCode and hover over a malicious `res://` path. Similar to document links, this requires a malicious project with crafted files.

- Source Code Analysis:
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

- Security Test Case:
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