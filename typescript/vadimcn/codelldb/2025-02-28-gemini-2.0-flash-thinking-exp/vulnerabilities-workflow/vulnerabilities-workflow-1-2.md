## Vulnerability List

- Vulnerability Name: HTML Injection in Webview via Python Scripting API

- Description:
    1. An attacker can craft a malicious Python script that utilizes the `codelldb.create_webview` API to create a webview panel with arbitrary HTML content.
    2. This malicious HTML content can include JavaScript code.
    3. If the `enable_scripts` option in `create_webview` is set to `true`, the injected JavaScript code will be executed within the context of the webview panel.
    4. An attacker could potentially use this to perform actions within the VSCode environment, access local resources, or steal sensitive information if the webview context has access to such resources.

- Impact:
    - High - Arbitrary HTML and JavaScript injection in VSCode webview.
    - If scripts are enabled in webview, this can lead to Cross-Site Scripting (XSS).
    - Potential for information disclosure or actions performed on behalf of the user, depending on the capabilities of the webview context when scripts are enabled.

- Vulnerability Rank: high

- Currently Implemented Mitigations:
    - By default, the `enable_scripts` option in `create_webview` is set to `false`, which disables JavaScript execution within the webview. This is a significant mitigation as it prevents XSS by default.

- Missing Mitigations:
    - Input sanitization for the `html` parameter in `create_webview` API. Even though scripts are disabled by default, it's best practice to sanitize HTML input to prevent any potential injection vulnerabilities if scripts are enabled or if the context of webview changes in the future.

- Preconditions:
    - The attacker must be able to execute Python scripts within the CodeLLDB debug adapter. This can be achieved through various launch configuration settings like `initCommands`, `preRunCommands`, `postRunCommands`, `exitCommands`, or by using Python expressions in watch window, debug console, conditional breakpoints, or logpoints.
    - For JavaScript execution, the `enable_scripts` parameter in the `create_webview` function must be explicitly set to `true` in the Python script.

- Source Code Analysis:
    1. File: `/code/extension/webview.ts`
    ```typescript
    import {
        window, debug, Uri, DebugSession, DebugSessionCustomEvent, ExtensionContext, WebviewPanel, ViewColumn
    } from "vscode";
    import { Dict } from './novsc/commonTypes';

    interface DebuggerPanel extends WebviewPanel {
        preserveOrphaned: boolean
    }

    export class WebviewManager {
        sessionPanels: Dict<Dict<DebuggerPanel>> = {};

        constructor(context: ExtensionContext) {
            let subscriptions = context.subscriptions;
            subscriptions.push(debug.onDidTerminateDebugSession(this.onTerminatedDebugSession, this));
            subscriptions.push(debug.onDidReceiveDebugSessionCustomEvent(this.onDebugSessionCustomEvent, this));
        }

        // ...

        createWebview(session: DebugSession, body: any) {
            let view_id = body.id;
            let panel = <DebuggerPanel>window.createWebviewPanel(
                'codelldb.webview',
                body.title || session.name,
                {
                    viewColumn: body.viewColumn != null ? body.viewColumn : ViewColumn.Active,
                    preserveFocus: body.preserveFocus
                },
                {
                    enableFindWidget: body.enableFindWidget,
                    enableScripts: body.enableScripts, // Scripts enabled based on this parameter
                    retainContextWhenHidden: body.retainContextWhenHidden,
                    enableScripts: body.enableScripts // Redundant declaration, but confirms script enabling control
                }
            );
            panel.webview.onDidReceiveMessage(e => {
                session.customRequest('_pythonMessage', { message: 'webviewDidReceiveMessage', id: view_id, inner: e });
            });
            panel.onDidDispose(() => {
                delete this.sessionPanels[session.id][view_id];
                session.customRequest('_pythonMessage', { message: 'webviewDidDispose', id: view_id });
            });
            if (body.html)
                panel.webview.html = body.html; // HTML content is directly set without sanitization
            panel.preserveOrphaned = body.preserveOrphaned

            // ...
        }
    }
    ```
    - The `createWebview` function in `webview.ts` directly sets the `webview.html` property to the `body.html` parameter received from the Python script, without any HTML sanitization.
    - The `enableScripts` option is passed directly to `window.createWebviewPanel`, controlling JavaScript execution in the webview.

    2. File: `/code/extension/main.ts`
    ```typescript
    // ...
    import * as webview from './webview';
    // ...

    class Extension {
        // ...
        webviewManager: webview.WebviewManager;
        // ...

        constructor(context: ExtensionContext) {
            // ...
            this.webviewManager = new webview.WebviewManager(context);
            // ...
        }

        // ...

        onDebugSessionCustomEvent(e: DebugSessionCustomEvent) {
            if (e.session.type == 'lldb') {
                if (e.event == '_pythonMessage') {
                    if (e.body.message == 'webviewCreate') {
                        this.webviewManager.createWebview(e.session, e.body); // `e.body` comes from Python script
                    } // ...
                }
            }
        }
    }
    ```
    - The `onDebugSessionCustomEvent` function in `main.ts` handles the `_pythonMessage` custom event and calls `this.webviewManager.createWebview` with `e.body` which originates from the Python script execution within the debug adapter.

- Security Test Case:
    1. Create a launch configuration in `launch.json` that allows execution of Python scripts in `initCommands`:
    ```json
    {
        "name": "Webview HTML Injection Test",
        "type": "lldb",
        "request": "launch",
        "program": "${workspaceFolder}/<executable file>",
        "args": [],
        "initCommands": [
            "script import debugger",
            "script webview = debugger.create_webview('<h1>Hello from debugger</h1><img src=\"x\" onerror=\"alert(\\'XSS_VULNERABILITY\\')\">', 'XSS Test', enable_scripts=True)"
        ]
    }
    ```
    2. Replace `<executable file>` with a valid executable for debugging (e.g., the `debuggee` example from test project if available and built).
    3. Start debugging with the "Webview HTML Injection Test" configuration.
    4. Observe if a webview panel titled "XSS Test" appears.
    5. Check if an alert box with the message "XSS_VULNERABILITY" is displayed when the webview is rendered.
    6. If the alert box is displayed, it confirms that arbitrary JavaScript code injected via the `create_webview` API has been executed, proving the HTML injection vulnerability and potential XSS if scripts are enabled.