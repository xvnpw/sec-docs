### Vulnerability List

- Vulnerability Name: Markdown Injection in Container Tooltips

- Description:
    1. An attacker can create a Docker container with a maliciously crafted name, image tag, volume name, or label containing Markdown code with command execution.
    2. When a user hovers over the affected Docker asset (container, image, volume) in the VSCode Docker Explorer, the extension renders a tooltip containing the asset's name or label.
    3. The `resolveTooltipMarkdown` function processes the tooltip content, including the attacker-controlled name/label, and marks the Markdown string as trusted with `enabledCommands: ['revealFileInOS']`.
    4. VSCode interprets the malicious Markdown code, specifically the `command:revealFileInOS` link, and executes the `revealFileInOS` command.
    5. If the `revealFileInOS` command is vulnerable to path traversal or other exploits, it could allow the attacker to trigger unintended actions or information disclosure.

- Impact:
    - High. An attacker could potentially leverage this vulnerability to execute commands on the user's machine or disclose sensitive information depending on the capabilities of the `revealFileInOS` command and the injected payload.

- Vulnerability Rank: high

- Currently Implemented Mitigations:
    - The `resolveTooltipMarkdown` function sets `isTrusted: { enabledCommands: ['revealFileInOS'] }`, which is intended to restrict the commands that can be executed via Markdown tooltips to only `revealFileInOS`.
    - Mitigation location: `/code/src/tree/resolveTooltipMarkdown.ts`

- Missing Mitigations:
    - Input sanitization for container names, image tags, volume names, and labels to remove or escape Markdown control characters before displaying them in tooltips.
    - Security review and hardening of the `revealFileInOS` command to ensure it cannot be misused for malicious purposes, such as path traversal or arbitrary file access. Consider if `revealFileInOS` should be allowed in tooltips at all, or if there are safer alternatives to display file paths.

- Preconditions:
    - VSCode with Docker extension installed.
    - Docker daemon running.
    - Attacker's ability to create Docker containers or influence container names, image tags, volume names, or labels displayed in the Docker Explorer.

- Source Code Analysis:
    1. **`/code/src/tree/resolveTooltipMarkdown.ts`**: The `resolveTooltipMarkdown` function compiles a template string using Handlebars and creates a `MarkdownString`. Crucially, it sets `result.isTrusted = { enabledCommands: ['revealFileInOS'] };`. This trusts the Markdown content and allows execution of the `revealFileInOS` command.
    ```typescript
    export async function resolveTooltipMarkdown(templateString: string, context: unknown): Promise<MarkdownString> {
        const handlebars = await getHandlebarsWithHelpers();

        const template = handlebars.compile(templateString);

        const markdownString = template(context);
        const result = new MarkdownString(markdownString, true);
        result.isTrusted = { enabledCommands: ['revealFileInOS'] }; // revealFileInOS is used in container tooltips
        return result;
    }
    ```
    2. **`/code/src/tree/containers/ContainerTreeItem.ts`**: The `resolveTooltipInternal` function in `ContainerTreeItem` calls `resolveTooltipMarkdown` with `containerTooltipTemplate`. This template is used to display container information, including the container name, which can be controlled by an attacker.
    ```typescript
    public async resolveTooltipInternal(actionContext: IActionContext): Promise<vscode.MarkdownString> {
        actionContext.telemetry.properties.tooltipType = 'container';

        const containerInspection = (await ext.runWithDefaults(client =>
            client.inspectContainers({ containers: [this.containerName] })
        ))?.[0];

        const handlebarsContext = {
            ...containerInspection,
            normalizedName: this.containerName,
        };
        return resolveTooltipMarkdown(containerTooltipTemplate, handlebarsContext);
    }
    ```
    3. The same pattern is used for `VolumeTreeItem.ts` and `ImageTreeItem.ts`.

- Security Test Case:
    1. Open VSCode with the Docker extension installed.
    2. Open a workspace folder.
    3. Open a terminal in VSCode.
    4. Run the following Docker command to create a container with a malicious name:
    ````bash
    docker run -d --name 'vuln-container-[test](command:revealFileInOS?%7B%22path%22:%22/etc/passwd%22%7D)' alpine sleep infinity
    ````
    5. Open the Docker Explorer in VSCode.
    6. Hover over the newly created container named `vuln-container-[test](command:revealFileInOS?%7B%22path%22:%22/etc/passwd%22%7D)` in the Containers view.
    7. Observe if the `/etc/passwd` file is revealed or an error related to file access is shown, indicating command execution via tooltip markdown injection.