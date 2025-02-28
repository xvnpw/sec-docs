# Material Icon Theme Extension Vulnerabilities

## XML External Entity (XXE) Injection in SVG Icon Processing  

**Description:**  
The extension processes SVG files (for example, when generating clones with the SVG–to–JSON conversion provided by the svgson library) without explicitly disabling external entity resolution. An attacker can craft an SVG file that includes a malicious DTD with external entities—such as one that references a sensitive file on the local system (e.g. "/etc/passwd"). When a victim loads a repository containing such an SVG, the parser (used in functions like `cloneIcon` in `/code/src/core/generator/clones/utils/cloning.ts`) will expand these external entities. By doing so, the attacker may cause local file disclosure and, if combined with further unsafe processing, could potentially trigger remote code execution.  

**Impact:**  
- Disclosure of sensitive local file contents.  
- Possible remote code execution in the context of the extension if malicious SVG data is further processed unsafely.  

**Vulnerability Rank:** High  

**Currently Implemented Mitigations:**  
- The project relies on the default configuration of the svgson library, with no explicit settings known to disallow DTD or external entity processing.  

**Missing Mitigations:**  
- Reconfigure the SVG parser (or switch to a securely hardened alternative) so that DTD processing and external entity resolution are disabled.  
- Implement additional input validation and sanitization of SVG contents obtained from repositories.  

**Preconditions:**  
- The victim opens a repository that contains one or more maliciously crafted SVG files containing external entity definitions.  

**Source Code Analysis:**  
- In `/code/src/core/generator/clones/utils/cloning.ts`, the function `cloneIcon` calls `readIcon` to obtain the raw SVG data and then processes it via `parse(baseContent)` (from the svgson library). No explicit options are passed to disable DTD/external entity processing.  

**Security Test Case:**  
- Create an SVG file that begins with an XML declaration and a DTD defining an external entity (for example, referencing `/etc/passwd`):  
  ```xml
  <?xml version="1.0"?>
  <!DOCTYPE svg [
    <!ENTITY xxe SYSTEM "file:///etc/passwd">
  ]>
  <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 32 32">
    <text x="0" y="15">&xxe;</text>
  </svg>
  ```  
- Include this SVG as one of the custom icons in a test repository.  
- Launch VS Code with the extension enabled and trigger the SVG processing (for example, by updating or generating clones).  
- Examine logs or the rendered icon to determine whether the external entity was resolved (e.g. if content from "/etc/passwd" appears or an error is logged), confirming the XXE vulnerability.

## Inadequate Validation of Custom SVG Icon File Paths  

**Description:**  
The extension supports custom icon associations by accepting file paths (often provided via a repository's configuration) that point to SVG icons. However, the helper function `getCustomIconPaths` (in `/code/src/core/helpers/customIconPaths.ts`) simply filters for strings that start with a dot or slash and then passes them to `resolvePath` (which uses `join(__dirname, '..', '..', …)`). Because there is no further check to ensure that these paths remain inside an approved directory, an attacker can supply a relative path (for example, using "../../") that escapes the intended icons folder.  

**Impact:**  
- Unauthorized reading of local files (if the extension loads SVGs from arbitrary locations).  
- In combination with other unsanitized behavior, this flaw might be exploited to trigger remote code execution.  

**Vulnerability Rank:** High  

**Currently Implemented Mitigations:**  
- Only advisory documentation is provided to users regarding where custom icons should reside; no programmatic enforcement is in place to limit file–path resolution.  

**Missing Mitigations:**  
- Enforce strict path normalization and apply a whitelist check so that any user–supplied file path for custom icons resolves strictly within the designated "icons" directory.  
- Reject or sanitize input paths that contain directory traversal sequences such as "../".  

**Preconditions:**  
- The victim loads a repository in which the configuration defines custom icon associations using manipulated (e.g. "../../") file paths.  

**Source Code Analysis:**  
- In `/code/src/core/helpers/customIconPaths.ts`, the code filters values from the file–association object using a simple regular expression (`/^[.\/]+/`) and then uses `resolvePath` to generate an absolute path. The lack of robust path "sandboxing" means an attacker can cause resolution of files outside of the intended directory.  

**Security Test Case:**  
- Create a test repository with a custom icon association setting that uses a relative path such as "../../sensitiveFile.svg".  
- Open the repository with the extension enabled and trigger the manifest generation process that reads these associations.  
- Verify (e.g. by examining the generated manifest or log output) that the resolved file paths point outside of the allowed directory, demonstrating the vulnerability.

## Arbitrary File Write via Unsanitized Custom Clone Name in Icon Cloning  

**Description:**  
The extension supports "icon clones" that are defined via custom clone configurations (for files, folders, or languages) in the user or repository settings. One of the required properties for a clone is "name", which is used to build the output file name for the cloned SVG icon. In the clone–generation process (especially in `/code/src/core/generator/clones/clonesGenerator.ts` and its helper functions such as `getIconName` in `/code/src/core/generator/clones/utils/cloneData.ts`), the user–supplied clone name is concatenated with other path components and a hash without proper sanitization. Should an attacker supply a clone configuration with a malicious "name" value that contains directory–traversal sequences (for example, "../evil"), the resulting path (constructed by using Node's `join` with the clones folder) may resolve outside the intended directory.  

**Impact:**  
- An attacker can force the extension to write (or even overwrite) cloned SVG files in locations outside the trusted "icons" directory.  
- If critical files are overwritten (or the clones are later loaded by a vulnerable SVG parser as described in the XXE issue), this may lead to remote code execution or compromise of the extension's integrity.  

**Vulnerability Rank:** High  

**Currently Implemented Mitigations:**  
- There is no sanitization, canonicalization, or whitelist enforcement on the clone "name" field in the custom clone configuration.  

**Missing Mitigations:**  
- Validate and sanitize the "name" value provided in custom clone configurations to disallow directory traversal patterns (e.g. any occurrences of "../" or other potentially dangerous substrings).  
- Enforce that the computed output file path lies strictly within the intended clones directory (for example, by comparing the resolved path against a base directory).  

**Preconditions:**  
- The victim loads a repository containing a custom clone definition (in any of the "files", "folders", or "languages" sections) where the "name" field includes directory–traversal syntax.  

**Source Code Analysis:**  
- In the clones generator (see `/code/src/core/generator/clones/clonesGenerator.ts`), the function `getCloneData` calls `getIconName(cloneOpts.name, base)` without sanitizing the provided clone name.  
- The computed clone file path is then determined by joining the directory of the base icon, a fixed subfolder (defined as `clonesFolder`), and the unsanitized clone name concatenated with a hash and file extension. If the clone name starts with "…/", the final resolved path will backtrack out of the clones folder.  

**Security Test Case:**  
- Prepare a test repository that defines a custom clone in its configuration (for files, folders, or languages) where the clone "name" is set to a string like "../evil".  
- Launch VS Code with this repository loaded and trigger the icon cloning process.  
- Inspect the file system (relative to the icons folder) to determine whether a file (for example, "../evil&lt;hash&gt;.svg") has been created outside the designated clones directory.  
- Confirm that the file ends up in an unintended location and that its content is derived from the base icon—demonstrating arbitrary file write.

## Command Injection via Malicious SVG File Names in SVG Color Linter  

**Description:**  
The SVG color checking script (`/code/src/scripts/svg/checkSvgColors.ts`) is designed to run a Git diff to identify staged SVG files and then invoke the `svg-color-linter` tool using Bun's `spawn` function. The script obtains a list of SVG file names from the Git diff output and then splits this output on whitespace before appending the resulting strings as arguments to the linter command. An attacker who supplies a malicious repository can commit an SVG file with a crafted name that starts with hyphen characters (for example, `--malicious.svg`) or includes characters that might be interpreted as command–line options. Because these file names are not validated or sanitized before being injected into the command array, the attacker may be able to manipulate the invoked command's options. In a worst–case scenario, if the linter interprets these options in an unsafe manner, the attacker might force the tool to execute arbitrary operations or commands in the extension's environment.  

**Impact:**  
- Manipulation of the command-line arguments passed to the external `svg-color-linter` tool may cause it to execute unintended options or operations.  
- In a chain with other vulnerabilities or if the linter does not securely handle unexpected flags, this could lead to execution of arbitrary commands and potentially enable remote code execution.  

**Vulnerability Rank:** High  

**Currently Implemented Mitigations:**  
- The script does not perform any sanitization or validation of the SV