# Threat Model Analysis for hexojs/hexo

## Threat: [Malicious Plugin Execution](./threats/malicious_plugin_execution.md)

*   **Description:** An attacker publishes a malicious Hexo plugin to the npm registry or another plugin source. The plugin appears legitimate but contains code that executes arbitrary commands on the administrator's machine during the `hexo generate` or `hexo deploy` process. The attacker might disguise the plugin as a useful utility (e.g., an image optimizer or SEO tool).
    *   **Impact:** Complete compromise of the administrator's machine, allowing the attacker to steal data, install malware, or use the machine for other malicious purposes. This could also lead to the compromise of the website itself if the attacker gains access to deployment credentials.
    *   **Hexo Component Affected:** `hexo.extend.filter`, `hexo.extend.generator`, `hexo.extend.helper`, `hexo.extend.processor`, `hexo.extend.tag`, `hexo.extend.deployer`, or any other plugin extension point. The vulnerability lies within the *plugin's code*, not Hexo's core code itself.
    *   **Risk Severity:** Critical
    *   **Mitigation Strategies:**
        *   **Strict Plugin Vetting:** Only install plugins from trusted sources (official Hexo plugin list, reputable GitHub repositories with a history of activity and positive reviews).
        *   **Code Review:** Before installing a plugin, review its source code (if available) for any suspicious code patterns (e.g., calls to `exec`, `spawn`, `require('child_process')`, network requests to unknown domains).
        *   **npm Audit:** Use `npm audit` to identify known vulnerabilities in the plugin and its dependencies *before* installing.
        *   **Sandboxing:** Run the Hexo build process in a sandboxed environment (e.g., a Docker container, a virtual machine) to isolate the plugin's execution and limit its access to the host system.
        *   **Least Privilege:** Run the Hexo CLI as a non-root user with limited privileges.
        *   **Dependency Pinning:** Use a `package-lock.json` or `yarn.lock` file to pin the exact versions of all dependencies, preventing unexpected updates that might introduce vulnerabilities.
        *   **Regular Updates:** Keep plugins updated to the latest versions to patch any known security vulnerabilities.

## Threat: [Theme-Based Code Injection](./threats/theme-based_code_injection.md)

*   **Description:** An attacker creates a malicious Hexo theme that contains JavaScript code designed to execute arbitrary commands on the administrator's machine during the build process. This is similar to the malicious plugin threat, but targets the theme instead. The attacker might distribute the theme through a seemingly legitimate website or theme repository.
    *   **Impact:** Similar to malicious plugins, this could lead to complete compromise of the administrator's machine and potentially the website.
    *   **Hexo Component Affected:** Theme files (EJS, Pug, Nunjucks, or other templating languages), theme JavaScript files, theme configuration files. The vulnerability is within the *theme's code*, not Hexo's core.
    *   **Risk Severity:** Critical
    *   **Mitigation Strategies:**
        *   **Theme Source Verification:** Download themes only from trusted sources (official Hexo theme list, reputable GitHub repositories).
        *   **Code Review:** Carefully examine the theme's source code, especially JavaScript files and templating files, for any suspicious code. Look for obfuscated code, calls to external resources, or attempts to access the file system.
        *   **Sandboxing:** Run the Hexo build process in a sandboxed environment (Docker container, VM).
        *   **Least Privilege:** Run Hexo as a non-root user.
        *   **Regular Updates:** Keep themes updated to the latest versions.

## Threat: [Sensitive Data Exposure in `_config.yml`](./threats/sensitive_data_exposure_in___config_yml_.md)

*   **Description:** The administrator accidentally includes sensitive information (API keys, database credentials, private keys) directly in the `_config.yml` file. This file is often committed to version control (e.g., Git), making the sensitive data publicly accessible if the repository is public or compromised.
    *   **Impact:** Exposure of sensitive credentials, potentially leading to unauthorized access to services, data breaches, or other security incidents.
    *   **Hexo Component Affected:** `_config.yml` (main configuration file).
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   **Environment Variables:** Store sensitive data in environment variables, *not* directly in `_config.yml`. Use a library like `dotenv` to load environment variables during development.
        *   **Configuration Management Tools:** For more complex deployments, consider using configuration management tools (e.g., Ansible, Chef, Puppet) to manage sensitive data securely.
        *   **`.gitignore`:** Ensure that any files containing sensitive data (e.g., `.env` files) are added to the `.gitignore` file to prevent them from being committed to version control.
        *   **Regular Audits:** Regularly review the `_config.yml` file and other configuration files to ensure that no sensitive information is present.
        *   **Pre-commit Hooks:** Use Git pre-commit hooks to automatically check for sensitive data in files before they are committed.

## Threat: [Outdated Hexo Core or Dependencies](./threats/outdated_hexo_core_or_dependencies.md)

*   **Description:** The administrator fails to update Hexo, Node.js, or the project's dependencies (including themes and plugins) to the latest versions. This leaves the system vulnerable to known security vulnerabilities that have been patched in newer releases.
    *   **Impact:** Increased risk of exploitation by known vulnerabilities, potentially leading to any of the impacts described in other threats (especially plugin or theme-based code injection).
    *   **Hexo Component Affected:** The entire Hexo installation, including the core `hexo` package, Node.js runtime, and all installed npm packages.
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   **Regular Updates:** Regularly update Hexo (`npm update -g hexo-cli`), Node.js, and all project dependencies (`npm update` or `yarn upgrade`).
        *   **Dependency Management:** Use a package manager (npm or yarn) to manage dependencies and track their versions.
        *   **Security Advisories:** Monitor security advisories for Hexo, Node.js, and npm packages (e.g., through `npm audit`, GitHub Security Advisories).
        *   **Automated Updates:** Consider using automated dependency update tools (e.g., Dependabot, Renovate) to help keep dependencies up to date.

