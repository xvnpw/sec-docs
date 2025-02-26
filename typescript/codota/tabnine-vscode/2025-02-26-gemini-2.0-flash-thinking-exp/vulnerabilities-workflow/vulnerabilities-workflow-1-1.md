* Vulnerability Name: Proxy URL Injection

* Description:
    1. The VSCode extension retrieves proxy settings from the VSCode configuration (`http.proxy`) and environment variables (`HTTPS_PROXY`, `https_proxy`, `HTTP_PROXY`, `http_proxy`) using the `getProxySettings` function in `proxyProvider.ts`.
    2. The retrieved proxy string is used to construct a `URL` object using `new URL(proxySettings)`.
    3. This `URL` object is then used to create `HttpsProxyAgent` in `getHttpsProxyAgent` function if proxy support is enabled, which is then used in `download.utils.ts` when downloading binary. Also proxy is passed as environment variable to binary process in `runBinary.ts`.
    4. If an attacker can control the proxy settings (either through VSCode configuration or environment variables), they can inject a malicious URL.
    5. When the extension creates `HttpsProxyAgent` or pass proxy to binary process with this malicious URL, it may lead to the extension routing network requests through an attacker-controlled proxy server.
    6. This can enable a Man-in-the-Middle (MITM) attack, where the attacker can intercept, monitor, and potentially modify network traffic between the extension and Tabnine backend servers, including binary download traffic and communication between extension and binary process.

* Impact:
    - **High**: Successful exploitation allows a MITM attack. An attacker can intercept and potentially modify network requests sent by the Tabnine extension. This could lead to:
        - Exfiltration of sensitive data transmitted by the extension and binary, including API keys or other credentials.
        - Injection of malicious responses from the attacker's proxy, potentially compromising the extension's functionality, binary functionality or user's workspace, including binary replacement with malicious one.
        - Bypassing intended security measures by redirecting traffic.

* Vulnerability Rank: High

* Currently Implemented Mitigations:
    - The project uses `HttpsProxyAgent` which is designed to handle HTTPS proxy connections. While `HttpsProxyAgent` provides secure proxying, it does not inherently prevent URL injection if the initial URL string is malicious.
    - The code checks for `tabnineExtensionProperties.useProxySupport` before using the proxy, which is a configuration setting to enable proxy usage. However, this does not mitigate the injection vulnerability itself if proxy support is enabled and a malicious URL is provided.

* Missing Mitigations:
    - **Input Validation and Sanitization**: The project lacks validation and sanitization of the proxy URL obtained from VSCode configuration and environment variables before creating a `URL` object.
    - **URL Parsing Library with Injection Prevention**: While `URL` constructor is used, it's crucial to ensure that the parsing process is robust against injection attacks. Consider using a dedicated URL parsing and validation library that explicitly prevents URL injection vulnerabilities and provides methods for sanitizing and validating URL components.

* Preconditions:
    - An attacker must be able to influence the proxy settings used by the VSCode extension. This could be achieved by:
        - Tricking a user into manually setting a malicious proxy URL in their VSCode `http.proxy` settings.
        - Exploiting other vulnerabilities to modify VSCode configuration files or environment variables that the extension reads.
        - If the extension is used in a shared or less secure environment where environment variables can be manipulated.

* Source Code Analysis:
    ```typescript
    File: /code/src/proxyProvider.ts
    export function getProxySettings(): string | undefined {
      let proxy: string | undefined = workspace // [1] Get proxy from VSCode config
        .getConfiguration()
        .get<string>("http.proxy");
      if (!proxy) {
        proxy = // [2] Get proxy from env vars
          process.env.HTTPS_PROXY ||
          process.env.https_proxy ||
          process.env.HTTP_PROXY ||
          process.env.http_proxy;
      }
      if (proxy?.endsWith("/")) { // [3] Remove trailing slash
        proxy = proxy.substr(0, proxy.length - 1);
      }
      return proxy; // [4] Return proxy string
    }

    export default function getHttpsProxyAgent(
      options: ProxyAgentOptions
    ): HttpsProxyAgent | undefined {
      const proxySettings = getProxySettings(); // [5] Get proxy settings

      if (!proxySettings || !tabnineExtensionProperties.useProxySupport) { // [6] Check if proxy is enabled
        return undefined;
      }

      const proxyUrl = new URL(proxySettings); // [7] Create URL object from proxy string

      const proxyOptions: HttpsProxyAgentOptions = { // [8] Construct HttpsProxyAgent options
        protocol: proxyUrl.protocol,
        port: proxyUrl.port,
        hostname: proxyUrl.hostname,
        pathname: proxyUrl.pathname,
        ca: options.ca,
        rejectUnauthorized: !options.ignoreCertificateErrors,
      };

      try {
        return new HttpsProxyAgent(proxyOptions); // [9] Create HttpsProxyAgent
      } catch (e) {
        return undefined;
      }
    }
    ```
    ```typescript
    File: /code/src/binary/runBinary.ts
    export default async function runBinary(
      additionalArgs: string[] = [],
      inheritStdio = false
    ): Promise<BinaryProcessRun> {
    ...
      const proxySettings = tabnineExtensionProperties.useProxySupport
        ? getProxySettings()
        : undefined;
    ...
      return runProcess(command, args, {
        stdio: inheritStdio ? "inherit" : "pipe",
        env: {
          ...process.env,
          https_proxy: proxySettings, // [1] Pass proxy to binary env
          HTTPS_PROXY: proxySettings, // [2] Pass proxy to binary env
          http_proxy: proxySettings,  // [3] Pass proxy to binary env
          HTTP_PROXY: proxySettings,  // [4] Pass proxy to binary env
        },
      });
    }
    ```
    ```typescript
    File: /code/src/utils/download.utils.ts
    export async function getHttpAgent(url: URL): Promise<Agent> {
      ...
      const proxyAgent = getHttpsProxyAgent({ ignoreCertificateErrors, ca }); // [1] Get proxy agent

      const httpModule = getHttpModule(url);
      return useProxySupport && proxyAgent
        ? proxyAgent // [2] Use proxy agent for http client
        : new httpModule.Agent({
            ca,
            rejectUnauthorized: !ignoreCertificateErrors,
          });
    }
    ```
    - The `getProxySettings` function retrieves the proxy string from VSCode configuration and environment variables without any validation (lines [1-4] in `proxyProvider.ts`).
    - The `getHttpsProxyAgent` function then creates a `URL` object directly from this potentially attacker-influenced string (line [7] in `proxyProvider.ts`).
    - This `URL` object is used to configure the `HttpsProxyAgent` (lines [8-9] in `proxyProvider.ts`), which is then used in `download.utils.ts` (lines [1-2]) for network requests and in `runBinary.ts` (lines [1-4]) to pass proxy settings to binary process. If a malicious URL is injected, `HttpsProxyAgent` will be configured to use a proxy server controlled by the attacker, and binary process will use attacker controlled proxy, leading to a MITM vulnerability.

* Security Test Case:
    1. **Setup Attacker Proxy:** Set up a simple HTTP proxy server (e.g., using `mitmproxy` or `Burp Suite`) on `attacker.com:8080` to intercept and log HTTP requests.
    2. **Configure VSCode Proxy:** In VSCode settings, set `http.proxy` to `http://attacker.com:8080`.
    3. **Install and Activate Extension:** Install and activate the Tabnine VSCode extension in VSCode instance where the proxy setting was changed.
    4. **Trigger Extension Network Request:** Perform actions in VSCode that trigger network requests from the Tabnine extension (e.g., code completion, status updates, etc.).
    5. **Verify Proxy Interception of Extension Traffic:** Check the logs of the attacker's proxy server. You should observe network requests originating from the Tabnine extension being routed through `attacker.com:8080`. This confirms that the extension is using the attacker-specified proxy for extension related traffic.
    6. **Trigger Binary Download:** If binary is not downloaded yet, trigger action that will cause binary download (e.g. start using Tabnine features that require binary).
    7. **Verify Proxy Interception of Binary Download Traffic:** Check the logs of the attacker's proxy server. You should observe network requests originating from the Tabnine extension for binary download being routed through `attacker.com:8080`. This confirms that the extension is using the attacker-specified proxy for binary download traffic.
    8. **Trigger Binary Network Request:** Perform actions in VSCode that trigger network requests from the Tabnine binary (e.g., code completion, status updates, etc.).
    9. **Verify Proxy Interception of Binary Traffic:** Check the logs of the attacker's proxy server. You should observe network requests originating from the Tabnine binary being routed through `attacker.com:8080`. This confirms that the extension is using the attacker-specified proxy for binary related traffic.
    10. **Attempt Data Modification (Optional):** Configure the attacker's proxy to modify responses from Tabnine backend servers. Observe if these modified responses affect the extension's behavior, further demonstrating the impact of the MITM vulnerability.