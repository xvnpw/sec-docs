- **Vulnerability Name:** Insecure Service Worker Request Method Handling  
  **Description:**  
  The service worker in the docs site intercepts network requests by checking that the hostname is on a fixed whitelist. However, it does not validate the HTTP method before processing the request. As a result, an attacker can send non–GET requests (such as POST or PUT) to an allowed hostname. These requests are then processed with the same caching and network–fetch logic as safe GET requests, allowing the attacker to potentially poison the cache with malicious content.  
  **Impact:**  
  An attacker can inject attacker–controlled responses into the cache. Subsequent users making GET requests to the affected endpoint may receive the poisoned cache content, which can lead to further exploitation (for example, cross–site scripting, content spoofing, or injection attacks).  
  **Vulnerability Rank:** High  
  **Currently Implemented Mitigations:**  
  - The service worker applies a hostname whitelist to determine whether a request should be handled.  
  - No specific filtering is applied to the HTTP method used, meaning all requests that meet the hostname criteria are processed.  
  **Missing Mitigations:**  
  - There is no verification to ensure that only safe, read–only HTTP methods (e.g. GET) are processed by the caching logic.  
  **Preconditions:**  
  - The docs site (or any whitelisted web resource) is publicly accessible.  
  - An attacker must be able to send a crafted non–GET request that is intercepted by the service worker.  
  **Source Code Analysis:**  
  - In the service worker’s `fetch` event handler (for example in `sw.js`), the code first checks whether the request’s hostname is part of a fixed whitelist.  
  - The code then immediately uses `event.request` to query the cache and perform a network fetch after “fixing” the URL—without checking the request’s HTTP method.  
  - No conditional statement (such as `if (event.request.method === 'GET') { … }`) is present to restrict caching logic solely to safe methods.  
  **Security Test Case:**  
  1. Deploy the docs site with the service worker registered.  
  2. Using a tool like cURL or Postman, send a non–GET request (for example, a POST) to a URL whose hostname is in the allowed list.  
     - Example (cURL):  
       ```bash
       curl -X POST "https://docs.yoursite.com/malicious" -d "attack=payload"
       ```  
  3. Inspect the browser’s developer tools or use a cache inspection utility to confirm whether the response from the POST request has been cached.  
  4. Make a subsequent GET request to the same URL and verify if the response is served from the cache and contains the modifyied, attacker–supplied content.  
  5. Confirmation of cache poisoning validates the vulnerability.

---

- **Vulnerability Name:** Webview Cross–Site Scripting via Unsanitized Markdown Parsing (with Potential Command URI Injection)  
  **Description:**  
  The extension creates a “Changelog” webview (see components in `src/webviews/Changelog.ts` and its registration in `src/extension.ts`) that loads the content of a local `CHANGELOG.md` file. This content is then parsed using the third–party `marked` library with its default settings, which allow raw HTML. Because the markdown output is passed directly to the webview without sanitization, any embedded HTML—including script tags or command–link URIs—will be rendered as is. In a supply–chain or update compromise (where not only the changelog but also theme or configuration files might be maliciously altered), an attacker could inject payloads that execute arbitrary JavaScript or trigger internal extension commands (such as those that update configuration).  
  **Impact:**  
  Exploitation of this vulnerability permits arbitrary JavaScript execution or the triggering of privileged extension commands (for instance, those that alter user settings). This could lead to hijacking of the extension’s behavior, exfiltration of sensitive user data, or unauthorized manipulation of the user’s editor environment. Given the elevated privileges of VS Code extensions, the consequences are severe.  
  **Vulnerability Rank:** High  
  **Currently Implemented Mitigations:**  
  - The `CHANGELOG.md` file is bundled with and maintained by the developers.  
  - The webview is configured with both `enableScripts: true` and `enableCommandUris: true`, which although necessary for functionality, also leave the interface open to attack if malicious content is injected.  
  **Missing Mitigations:**  
  - The `marked` library is used without switching on a “safe mode” (or without enabling HTML escaping) so that raw HTML is not filtered out.  
  - There is no additional sanitization of the parsed markdown before it is rendered in the webview.  
  - There is no validation performed on dynamically imported theme or configuration data, which could also serve as an attack vector if compromised.  
  **Preconditions:**  
  - The attacker must be capable of modifying or replacing the `CHANGELOG.md` file (or other configuration/theme files through a supply–chain/update compromise).  
  - The user must trigger the display of the changelog (for example, via executing the `oneDarkPro.showChangelog` command).  
  **Source Code Analysis:**  
  - In `src/webviews/Changelog.ts`, the code constructs the path to `CHANGELOG.md` (using a relative join, for example, `path.join(__dirname, '../../', 'CHANGELOG.md')`) and reads its contents.  
  - The content is then decoded (for instance, via a `TextDecoder`) and passed directly to `marked.parse(content)` without any sanitization step.  
  - Because `marked`’s default configuration permits raw HTML, any injected HTML—including `<script>` tags or command URIs—is rendered in the webview.  
  - The webview is created with `enableCommandUris: true`, which means that any embedded command links (for example, `<a href="command:oneDarkPro.setBold">`) are active and can be accidentally triggered by the user.  
  **Security Test Case:**  
  1. Manually modify the bundled `CHANGELOG.md` file to include a malicious payload. For example, append a line such as:  
     - `<script>window.alert('XSS');</script>`  
     or a command link:  
     - `<a href="command:oneDarkPro.setBold">Click here</a>`  
  2. Reload or activate the extension in VS Code and open the changelog by executing the `oneDarkPro.showChangelog` command.  
  3. Observe whether the malicious JavaScript executes (such as an alert box appearing) or whether clicking on the injected command link causes the corresponding extension command (for example, updating configuration) to run.  
  4. If either occurs, the vulnerability is confirmed.