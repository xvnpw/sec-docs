## Vulnerability List:

- Vulnerability Name: Remote Code Execution via Custom Property/Description Generators

- Description:
    1. A threat actor can craft a malicious VSCode launch configuration (`launch.json`).
    2. Within this configuration, the threat actor sets the `customDescriptionGenerator` or `customPropertiesGenerator` fields to arbitrary JavaScript code as a string.
    3. When a user opens this workspace and starts a debugging session using the malicious configuration, the VSCode extension reads and applies this configuration.
    4. The extension then uses the provided string as a JavaScript function in the debugger's object inspection features.
    5. This injected JavaScript code is executed within the extension's context, allowing the threat actor to perform arbitrary actions on the user's machine with the privileges of the VSCode extension.

- Impact:
    - Remote Code Execution (RCE). An attacker can execute arbitrary code on the machine where the VSCode extension is running. This could lead to:
        - Data exfiltration: Stealing sensitive information from the user's workspace or machine.
        - Malware installation: Installing malware or backdoors on the user's machine.
        - Privilege escalation: Gaining higher privileges on the user's system.
        - Workspace manipulation: Modifying or deleting files in the user's workspace.

- Vulnerability Rank: Critical

- Currently Implemented Mitigations:
    - None. The project currently directly uses the string values from `customDescriptionGenerator` and `customPropertiesGenerator` as JavaScript functions without any sanitization or validation.

- Missing Mitigations:
    - Input sanitization: The extension should sanitize or completely disallow user-provided JavaScript code in configuration fields.
    - Code execution prevention: Avoid using `eval` or similar functions to execute arbitrary strings as code from configuration.
    - Principle of least privilege: If code execution from configuration is necessary, ensure it runs with the minimal required privileges.

- Preconditions:
    - The user must open a workspace containing a malicious `launch.json` file.
    - The user must start a debugging session using the malicious launch configuration.

- Source Code Analysis:
    1. The vulnerability originates from the configuration options `customDescriptionGenerator` and `customPropertiesGenerator` defined in `/code/src/configuration.ts` within the `IBaseConfiguration` interface. These options allow users to provide custom JavaScript code as strings to generate object descriptions and properties in the debugger.
    ```typescript
    export interface IBaseConfiguration extends IMandatedConfiguration {
        ...
        /**
         * Function used to generate the description of the objects shown in the debugger
         * e.g.: "function (defaultDescription) { return this.toString(); }"
         */
        customDescriptionGenerator?: string;

        /**
         * Function used to generate the custom properties to show for objects in the debugger
         * e.g.: "function () { return {...this, extraProperty: 'otherProperty' } }"
         */
        customPropertiesGenerator?: string;
        ...
    }
    ```
    2. The file `/code/src/adapter/variableStore.ts` demonstrates how these configuration options are utilized to execute arbitrary code.
    3. The `extractFunctionFromCustomGenerator` function is responsible for parsing the string from configuration and converting it into an executable JavaScript function using `parseSource` and `statementsToFunction` and `generate` from `astring`.
    ```typescript
    const extractFunctionFromCustomGenerator = (
      parameterNames: string[],
      generatorDefinition: string,
      catchAndReturnErrors: boolean,
    ) => {
      const code = statementsToFunction(
        parameterNames,
        parseSource(generatorDefinition),
        catchAndReturnErrors,
      );
      return generate(code);
    };
    ```
    4. The `VariableContext` class holds the configuration settings, including `customDescriptionGenerator` and `customPropertiesGenerator`.
    ```typescript
    class VariableContext {
      ...
      public get customDescriptionGenerator() {
        return this.settings.customDescriptionGenerator;
      }
      ...
      constructor(
        ...
        private readonly settings: IContextSettings,
        ...
      ) {
        ...
      }
      ...
    }
    ```
    5. The `createObjectPropertyVars` function in `VariableContext` uses these custom generators. It calls `evaluateCodeForObject` to execute the code from `customPropertiesGenerator`.
    ```typescript
    class VariableContext {
      ...
      public async createObjectPropertyVars(
        object: Cdp.Runtime.RemoteObject,
        evaluationOptions?: Dap.EvaluationOptions,
      ): Promise<Variable[]> {
        const properties: (Promise<Variable[]> | Variable[])[] = [];

        if (this.settings.customPropertiesGenerator) {
          const { result, errorDescription } = await this.evaluateCodeForObject(
            object,
            this.settings.customPropertiesGenerator,
            [],
          );
          ...
        }
        ...
      }
      ...
    }
    ```
    6. The `evaluateCodeForObject` function executes the string as JavaScript code using `cdp.Runtime.callFunctionOn`. This allows execution of arbitrary code within the context of the debugging session, leading to RCE.
    ```typescript
    class VariableContext {
      ...
      private async evaluateCodeForObject(
        object: Cdp.Runtime.RemoteObject,
        functionDeclaration: string,
        argumentsToEvaluateWith: string[],
      ): Promise<{ result?: Cdp.Runtime.RemoteObject; errorDescription?: string }> {
        try {
          const customValueDescription = await this.cdp.Runtime.callFunctionOn({
            objectId: object.objectId,
            functionDeclaration,
            arguments: argumentsToEvaluateWith.map(toCallArgument),
          });
          ...
        } catch (e) {
          return { errorDescription: e.stack || e.message || String(e) };
        }
      }
      ...
    }
    ```
    7. Visualization of code flow:

    ```mermaid
    graph LR
        A[launch.json: customPropertiesGenerator/customDescriptionGenerator] --> B(configuration.ts: IBaseConfiguration);
        B --> C(variableStore.ts: VariableContext);
        C --> D(variableStore.ts: createObjectPropertyVars);
        D --> E(variableStore.ts: evaluateCodeForObject);
        E --> F(cdp.Runtime.callFunctionOn);
        F --> G[Code Execution];
    ```

- Security Test Case:
    1. Create a new VSCode workspace.
    2. Create a file named `launch.json` in the `.vscode` folder of the workspace.
    3. Add the following configuration to `launch.json`:
    ```json
    {
      "version": "0.2.0",
      "configurations": [
        {
          "type": "node",
          "request": "launch",
          "name": "Malicious Config",
          "program": "${workspaceFolder}/index.js",
          "customDescriptionGenerator": "function() { process.exit(1); }",
          "customPropertiesGenerator": "function() { process.exit(1); }"
        }
      ]
    }
    ```
    4. Create a file named `index.js` in the workspace root (or any file specified in "program") with simple JavaScript code, for example: `console.log("Hello, world!");`.
    5. Open `index.js` and start debugging using the "Malicious Config" configuration.
    6. Observe that VSCode immediately terminates or becomes unresponsive after starting the debug session, indicating that the `process.exit(1)` command injected via `customDescriptionGenerator` and `customPropertiesGenerator` was successfully executed. You can also try other commands like `require('child_process').execSync('touch /tmp/pwned');` to verify file system access.