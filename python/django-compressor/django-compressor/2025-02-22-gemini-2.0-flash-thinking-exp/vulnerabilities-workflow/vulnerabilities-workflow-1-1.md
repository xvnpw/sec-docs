### Vulnerability List

- Vulnerability Name: Command Injection in Precompiler Commands
- Description:
    1. An attacker, assuming they can influence Django settings (e.g., through a separate vulnerability in the application using django-compressor), modifies the `COMPRESS_PRECOMPILERS` setting.
    2. The attacker injects a malicious command into the command string of one of the precompilers. For example, they might set a precompiler for a specific mimetype to execute a command like `touch /tmp/pwned; {infile} {outfile}`.
    3. The attacker then triggers a scenario where django-compressor processes a file (either a legitimate file or a crafted one) that is associated with the mimetype they configured with the malicious command. This could be done by rendering a Django template that includes a `<style type="text/x-exploit">` block if they configured 'text/x-exploit' as the vulnerable mimetype.
    4. When django-compressor processes this file, the `CompilerFilter` class will execute the command specified in `COMPRESS_PRECOMPILERS`, including the attacker's injected command, using `subprocess.Popen` with `shell=True`.
    5. The injected command is executed on the server, leading to arbitrary code execution.
- Impact:
    - Remote Code Execution (RCE): Successful exploitation allows the attacker to execute arbitrary commands on the server hosting the Django application. This can lead to complete compromise of the server, data theft, data manipulation, and further attacks on internal systems.
- Vulnerability Rank: critical
- Currently Implemented Mitigations:
    - None. The code relies on the security of the Django settings and assumes that `COMPRESS_PRECOMPILERS` is configured and managed only by trusted developers. There is no input validation or sanitization within `CompilerFilter` to prevent command injection.
- Missing Mitigations:
    - Input Sanitization: Implement robust input sanitization for the command strings and any options used in `CompilerFilter`. This could involve using parameterized commands or strictly validating characters allowed in commands and filenames. However, sanitizing shell commands is complex and error-prone.
    - Avoid `shell=True`:  Modify `CompilerFilter` to avoid using `shell=True` in `subprocess.Popen`. Instead, execute commands directly as a list of arguments. This significantly reduces the risk of command injection but might require refactoring how precompiler commands are defined and used.
    - Documentation and Warnings: Add clear and prominent documentation warning developers about the risks of allowing untrusted input to influence `COMPRESS_PRECOMPILERS`. Emphasize the importance of secure configuration management and access control to Django settings.
- Preconditions:
    - Attacker must have the ability to modify Django project settings, specifically the `COMPRESS_PRECOMPILERS` setting. This is typically not directly exposed to external attackers but could be a result of other vulnerabilities or misconfigurations in the application that uses django-compressor.
    - The application must be configured to use precompilers defined in `COMPRESS_PRECOMPILERS`.
    - An attacker needs to trigger the compression process for content that will utilize the precompiler with the injected command.
- Source Code Analysis:
    1. File: `/code/compressor/conf.py`
    ```python
    class CompressorConf(AppConf):
        # ...
        PRECOMPILERS = (
            # ('text/coffeescript', 'coffee --compile --stdio'),
            # ('text/less', 'lessc {infile} {outfile}'),
            # ...
        )
        # ...
    ```
    - `COMPRESS_PRECOMPILERS` is defined as a setting that holds tuples of mimetype and command. This setting is intended for configuration by developers.

    2. File: `/code/compressor/filters/base.py`
    ```python
    class CompilerFilter(FilterBase):
        command = None
        options = ()
        # ...
        def input(self, **kwargs):
            # ...
            try:
                command = self.command.format(**options)
                proc = subprocess.Popen(
                    command,
                    shell=True, # <--- Vulnerable because shell=True is used
                    cwd=self.cwd,
                    stdout=self.stdout,
                    stdin=self.stdin,
                    stderr=self.stderr,
                )
                # ...
            except (IOError, OSError) as e:
                raise FilterError(
                    "Unable to apply %s (%r): %s"
                    % (self.__class__.__name__, self.command, e)
                )
            # ...
    ```
    - The `CompilerFilter.input` method formats the `self.command` string using `self.command.format(**options)` and then executes it using `subprocess.Popen(command, shell=True, ...)`.
    - The use of `shell=True` is the root cause of the command injection vulnerability. When `shell=True`, the command string is interpreted by the shell, allowing for shell metacharacters and command chaining to be injected if the command string or the `options` dictionary are not properly sanitized.
    - The `options` dictionary can contain values like `infile` and `outfile` which are filenames and could potentially be attacker-influenced or constructed in a way that aids injection.

- Security Test Case:
    1. Setup:
        - Configure a Django project using django-compressor.
        - In `settings.py`, add a malicious precompiler to `COMPRESS_PRECOMPILERS`:
        ```python
        COMPRESS_PRECOMPILERS = [
            ('text/x-pwned', 'touch /tmp/django_compressor_pwned_{cachekey}; {infile} {outfile}')
        ]
        ```
        - Ensure `COMPRESS_ENABLED = True` and add 'compressor' to `INSTALLED_APPS`.
        - Create a template that will trigger the precompiler:
        ```html
        {% load compress %}
        {% compress css %}
        <style type="text/x-pwned">body { color: red; }</style>
        {% endcompress %}
        ```
        - Create a view that renders this template and map it to a URL.

    2. Execution:
        - Access the URL that renders the template in a web browser or using `curl`. This will trigger the `compress` template tag and the processing of the `<style type="text/x-pwned">` block.

    3. Verification:
        - Check if the file `/tmp/django_compressor_pwned_<cachekey>` exists on the server. Replace `<cachekey>` with an expected cache key value or check for any file starting with `/tmp/django_compressor_pwned_`.
        - If the file exists, it confirms that the `touch` command injected through `COMPRESS_PRECOMPILERS` was successfully executed, demonstrating command injection.

This test case proves that by controlling `COMPRESS_PRECOMPILERS` and triggering the compressor, an attacker can achieve command execution.