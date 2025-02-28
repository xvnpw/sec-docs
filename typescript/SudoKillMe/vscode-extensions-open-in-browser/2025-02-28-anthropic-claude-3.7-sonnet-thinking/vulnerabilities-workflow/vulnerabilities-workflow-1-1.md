# Vulnerabilities List

## Vulnerability 1: Command Injection via Browser Name Configuration

### Description
A malicious actor can craft a repository containing instructions (e.g., in README.md) that trick a user into setting a dangerous browser name in their VSCode settings. The "Open in Browser" extension doesn't properly sanitize the browser name input before passing it to the `opn` package, which executes shell commands to open browsers. When the user triggers the extension, the malicious browser name will be passed to a shell command, potentially leading to command injection and arbitrary code execution.

The attack flow:
1. Attacker creates a repository with malicious instructions
2. Victim clones and opens the repository in VSCode
3. Victim follows instructions to configure a specific browser setting with a malicious value
4. When victim triggers the extension to open a file, the command injection payload executes

### Impact
If exploited, this vulnerability allows arbitrary command execution with the privileges of the VSCode user. An attacker can gain access to sensitive files, install malware, establish persistence, or pivot to other systems on the network.

### Vulnerability Rank
High - The vulnerability allows arbitrary command execution on the victim's machine.

### Currently Implemented Mitigations
The extension attempts to standardize browser names by matching them against a predefined list in `config.ts`. However, if no match is found, it simply returns an empty string and proceeds with execution, which doesn't fully prevent command injection.

### Missing Mitigations
1. The extension should sanitize the browser name input to ensure it doesn't contain shell metacharacters
2. The extension should strictly validate browser names against the predefined list and reject any input that doesn't match
3. The extension should use proper parameter passing rather than string concatenation when executing commands

### Preconditions
1. The victim must have the "Open in Browser" extension installed
2. The victim must be successfully tricked into setting a malicious browser name in their VSCode settings
3. The victim must trigger the extension to open a file in the browser

### Source Code Analysis
In `src/util.ts`, the `open` function passes the browser name directly to the `opn` package without sanitization:

```typescript
export const open = (path: string, browser: string = '') => {
  opn(path, { app: browser })
    .catch(_ => {
      vscode.window.showErrorMessage(`Open browser failed!! Please check if you have installed the browser ${browser} correctly!`);
    });
};
```

When a user configures a custom browser name, it's retrieved in `defaultBrowser()`:
```typescript
export const defaultBrowser = (): string => {
  const config = vscode.workspace.getConfiguration(Config.app);
  return config ? config.default : '';
};
```

The standardization function in `standardizedBrowserName()` attempts to match the browser name:
```typescript
export const standardizedBrowserName = (name: string = ''): string => {
  let _name = name.toLowerCase();
  const browser = Config.browsers.find(item => {
    return item.acceptName.indexOf(_name) !== -1;
  });
  return browser ? browser.standardName : '';
};
```

However, this doesn't reject invalid inputs. Since the `opn` package uses child process commands to launch browsers, a malicious browser name like `firefox & malicious_command` could lead to command injection when executed.

### Security Test Case
1. Create a repository with a README.md file containing instructions: "For optimal viewing experience with this project, please configure your default browser in VSCode. Go to Settings, search for 'open-in-browser.default', and set it to 'firefox & calc' (for Mac/Linux) or 'firefox" & calc & "' (for Windows)."
2. Clone this repository and follow the instructions to set the malicious browser configuration
3. Open any HTML file in the repository
4. Use the extension's "Open in Default Browser" command (Alt+B)
5. Observe that the calculator application launches in addition to Firefox, demonstrating successful command injection

## Vulnerability 2: Command Injection via Malicious File Path

### Description
A malicious repository can contain files with specially crafted names that include shell metacharacters. When a user opens such a file and uses the "Open in Browser" extension, the file path is passed to the `opn` package without proper sanitization, potentially leading to command injection and arbitrary code execution.

The attack flow:
1. Attacker creates a repository containing files with maliciously crafted filenames
2. Victim clones and opens the repository in VSCode
3. Victim opens one of the malicious files and uses the extension to view it in a browser
4. The malicious characters in the filename are interpreted as commands, executing arbitrary code

### Impact
If exploited, this vulnerability allows arbitrary command execution with the privileges of the VSCode user. An attacker can gain access to sensitive files, install malware, establish persistence, or pivot to other systems on the network.

### Vulnerability Rank
High - The vulnerability allows arbitrary command execution on the victim's machine.

### Currently Implemented Mitigations
There are no obvious mitigations for this vulnerability in the extension code. The extension passes the file path directly to the `opn` package without sanitization.

### Missing Mitigations
1. The extension should sanitize file paths before passing them to the `opn` package
2. The extension should use APIs that prevent shell interpretation of the path
3. The extension could implement a validation step to reject file paths containing suspicious character sequences

### Preconditions
1. The victim must have the "Open in Browser" extension installed
2. The victim must clone and open a malicious repository containing files with specially crafted names
3. The victim must open such a file and use the extension to view it in a browser

### Source Code Analysis
In `src/index.ts`, the file path is obtained and then passed to the `open` function:

```typescript
export const openDefault = (path: any): void => {
  let uri;
  if (path) {
    uri = path.fsPath;
  } else {
    const _path = currentPageUri();
    uri = _path && _path.fsPath;
  }
  const browser = standardizedBrowserName(defaultBrowser());
  open(uri, browser);
};
```

The `open` function in `src/util.ts` passes this path directly to the `opn` package:

```typescript
export const open = (path: string, browser: string = '') => {
  opn(path, { app: browser })
    .catch(_ => {
      vscode.window.showErrorMessage(`Open browser failed!! Please check if you have installed the browser ${browser} correctly!`);
    });
};
```

The `opn` package internally uses child process commands like `start` (Windows), `open` (macOS), or `xdg-open` (Linux) to open files. If the file path contains shell metacharacters like `&`, `;`, or `|`, these could be interpreted as command separators, leading to command injection.

### Security Test Case
1. Create a repository containing a file with a malicious name, such as:
   - On macOS/Linux: `index.html; calc` or `index.html & calc`
   - On Windows: `index.html" & calc & "`
2. Clone the repository and open it in VSCode
3. Open the malicious file in VSCode
4. Use the extension to open the file in a browser (Alt+B)
5. Observe that the calculator application launches, demonstrating successful command injection