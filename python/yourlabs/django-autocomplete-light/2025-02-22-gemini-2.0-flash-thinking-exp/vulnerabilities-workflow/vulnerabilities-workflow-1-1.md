### Vulnerability List

- Vulnerability Name: **Command Injection in changelog.py**
- Description:
    - The `changelog.py` script takes a version tag as a command-line argument (`sys.argv[1]`).
    - This tag is then directly incorporated into shell commands executed by the script using `subprocess.check_output`.
    - Specifically, the tag is used in the following commands:
        - `git log --pretty=format:'%h %D' {last_release}..`
        - `git log --format='%an--sep--%B' -n1 {sha}`
        - `git log --format='%as' -n1 {sha}`
    - If an attacker can control the value of `sys.argv[1]` (the version tag), they can inject arbitrary shell commands that will be executed by the script.
    - In a real-world scenario, while an external attacker cannot directly control the execution of `changelog.py`, if there's a workflow or automation that uses user-provided data to generate release tags and subsequently runs this script, it could be exploited. For example, if a CI/CD pipeline uses a user-provided version tag from a Git tag or branch name to trigger a release process that includes running `changelog.py`.

- Impact:
    - **Critical**
    - Successful command injection can allow the attacker to execute arbitrary commands on the server with the privileges of the user running the `changelog.py` script.
    - This can lead to complete compromise of the server, including data theft, modification, and denial of service.

- Vulnerability Rank: **Critical**

- Currently implemented mitigations:
    - **None**
    - The script directly uses the user-provided version tag in shell commands without any sanitization or validation.

- Missing mitigations:
    - **Input Sanitization:** The version tag from `sys.argv[1]` should be strictly validated and sanitized before being used in shell commands.
    - **Command Parameterization:** Instead of string formatting, use command parameterization features provided by `subprocess` to pass arguments safely to shell commands, preventing injection. For example, use list for `subprocess.run` arguments and avoid `shell=True`.

- Preconditions:
    - An attacker needs to find a way to influence the input to `changelog.py` script. This is typically not directly exposed to external attackers. However, if the release process is automated and triggered by user-controlled inputs (e.g., git tags, branch names, CI/CD pipeline triggers), then exploitation is possible.

- Source code analysis:
    - File: `/code/changelog.py`

    ```python
    import subprocess
    import sys

    tag = sys.argv[1]

    git_log = subprocess.check_output(
        f"git log --pretty=format:'%h %D' {last_release}..", # Vulnerable line 1
        shell=True,
    ).decode('utf8').split('\n')

    # ...

    author, description = subprocess.check_output(
        f"git log --format='%an--sep--%B' -n1 {sha}", # Vulnerable line 2
        shell=True,
    ).decode('utf8').split('\n')[0].split('--sep--')

    # ...

    date = subprocess.check_output(
        f"git log --format='%as' -n1 {sha}", # Vulnerable line 3
        shell=True,
    ).decode('utf8').strip()
    ```
    - The code directly embeds the `tag` variable, which is derived from `sys.argv[1]`, into f-strings that are then executed as shell commands using `subprocess.check_output(..., shell=True)`.
    - There is no input validation or sanitization performed on the `tag` variable before it's used in the shell commands.
    - This allows for command injection because a malicious tag value could contain shell metacharacters or commands that would be interpreted by the shell when executing the `git log` commands.

- Security test case:
    - Pre-requisite: Need to be able to execute `changelog.py` script. Assume we can simulate the release process locally.
    - Steps:
        1. Prepare a malicious version tag. For example, `v1.0.0; touch /tmp/pwned`. This tag attempts to execute the `touch /tmp/pwned` command after the intended version tag part.
        2. Execute the `changelog.py` script with the malicious tag as a command-line argument: `./changelog.py 'v1.0.0; touch /tmp/pwned'`
        3. Check if the command injection was successful. In this case, check if the file `/tmp/pwned` was created.
        4. If the file `/tmp/pwned` exists, it confirms that the command injection vulnerability is present.