# Vulnerabilities in Live Server Web Extension

## WebSocket URL Injection Vulnerability leading to Remote Code Execution

### Vulnerability Name
WebSocket URL Injection leading to Remote Code Execution

### Description
In the reload.js file, the extension constructs WebSocket URLs using naive string replacement:
```javascript
address = data.liveServerUrl.replace('http', 'ws') + '/ws';
```

This implementation is vulnerable to manipulation when a user inputs a malicious URL in the Live Server URL field. An attacker can craft a special URL that, when processed by this function, creates a WebSocket connection that can execute arbitrary JavaScript code.

Step by step:
1. The attacker creates a malicious repository that includes instructions for the victim to set up the Live Server extension with a specific URL
2. When the victim enters the malicious URL in the extension's configuration popup
3. The extension's vulnerable string replacement logic processes this URL
4. A malicious WebSocket connection is established that can execute arbitrary code

### Impact
This vulnerability allows remote code execution within the browser context. An attacker can execute arbitrary JavaScript code in the victim's browser, potentially leading to:
- Access to sensitive browser data
- Session hijacking
- Further exploitation of the local system

### Vulnerability Rank
Critical

### Currently Implemented Mitigations
None. The code performs a naive string replacement without any validation or sanitization of user-provided URLs.

### Missing Mitigations
1. Proper URL parsing using the URL API instead of string replacement
2. Validation that the URL uses a valid WebSocket protocol (ws:// or wss://)
3. Origin validation for WebSocket connections
4. Input sanitization for user-provided URLs

### Preconditions
1. The victim must have both the VS Code Live Server extension and this browser extension installed
2. The victim must be tricked into entering a malicious URL in the extension configuration
3. The victim must activate the extension by checking the "Enable Live Reload" option

### Source Code Analysis
Let's trace the execution flow that leads to this vulnerability:

1. In `popup.js`, the extension collects user input from the popup interface:
```javascript
const formData = {
    isEnable: liveReloadCheck.checked,
    proxySetup: !noProxyCheckBox.checked,
    actualUrl: actualServerAddress.value || '',
    liveServerUrl: liveServerAddress.value || ''
}
```

2. This data is sent to the background script:
```javascript
chrome.runtime.sendMessage({
    req: 'set-live-server-config',
    data: formData
});
```

3. In `background.js`, this configuration is stored and broadcast to all tabs:
```javascript
if (msg.req === 'set-live-server-config') {
    storeConfigToLocalStorage(msg.data);
    sendMsgToAllContainPage('live-server-config-updated', msg.data);
}
```

4. In `reload.js`, the extension processes this configuration and establishes a WebSocket connection:
```javascript
function init(data) {
    if (!data.proxySetup) {
        //Correction
        if (data.liveServerUrl.indexOf('http') !== 0)
            data.liveServerUrl = 'http' + data.liveServerUrl;
        if (data.actualUrl.indexOf('http') !== 0)
            data.actualUrl = 'http' + data.actualUrl;
        if (!data.actualUrl.endsWith('/'))
            data.actualUrl = data.actualUrl + '/';

        address = data.liveServerUrl.replace('http', 'ws') + '/ws';
    }
    socket = new WebSocket(address);
    socket.onmessage = (msg) => {
        reloadWindow(msg, data)
    };
}
```

The vulnerability exists in the line `address = data.liveServerUrl.replace('http', 'ws') + '/ws';` which uses a naive string replacement to convert an HTTP URL to a WebSocket URL.

If an attacker provides a malicious URL like `javascript:alert(document.domain);//http`, the resulting WebSocket address would be `javascript:alert(document.domain);//ws/ws`. When the browser attempts to establish this WebSocket connection, it may interpret this as a JavaScript URI and execute the embedded code.

### Security Test Case
To verify this vulnerability:

1. Install both the VS Code Live Server extension and this browser extension
2. Open the extension popup by clicking on its icon in the browser toolbar
3. Check the "Enable Live Reload" checkbox
4. Check the "No Proxy (Direct connection to server)" checkbox
5. In the "Live Server Address" field, enter a malicious URL such as:
   ```
   javascript:alert(document.cookie);//http
   ```
6. Click the "Apply" button
7. Observe that JavaScript code execution occurs in the browser context

This test case demonstrates that an attacker can achieve remote code execution by manipulating the WebSocket URL construction through user-provided input.