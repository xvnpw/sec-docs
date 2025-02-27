### Vulnerability List

* Vulnerability Name: Lack of Input Validation in Configuration Leads to Potential Exposure to Malicious Content
* Description:
    1. The Live Server Web Extension allows users to configure "Actual Server Address" and "Live Server Address" through the extension's popup UI.
    2. The extension stores these URLs in the browser's local storage without any validation.
    3. In `reload.js`, the extension uses the configured "Live Server Address" to establish a WebSocket connection.
    4. If a user is tricked into entering a malicious WebSocket URL as the "Live Server Address", the extension will connect to this malicious server.
    5. If the malicious server sends a 'reload' message, the extension will reload the current webpage.
    6. If the "Actual Server Address" is also pointed to a malicious server (or a legitimate server that has been compromised), the reloaded page could contain malicious content.
    7. This can lead to a scenario where a user, due to misconfiguration, is persistently exposed to malicious content every time a file change is detected by the VS Code Live Server and triggers a reload.
* Impact:
    If a user is tricked into configuring the extension with malicious URLs, they could be persistently exposed to malicious content injected into webpages served from the "Actual Server Address" whenever VS Code Live Server detects changes and triggers a reload. This could lead to various attacks depending on the nature of the malicious content, including but not limited to phishing, drive-by downloads, and cross-site scripting if the malicious server content exploits vulnerabilities in the target website or browser.
* Vulnerability Rank: high
* Currently Implemented Mitigations: None. The extension does not validate or sanitize the URLs provided by the user.
* Missing Mitigations:
    - Input validation for "Actual Server Address" and "Live Server Address" in `popup/popup.js`.
    - URL format validation (e.g., checking for valid protocols, hostnames).
    - Potentially, prompting a warning to the user when they are about to connect to a WebSocket server on a different domain than the current page, or outside of localhost.
* Preconditions:
    1. User has installed the Live Server Web Extension.
    2. User is using the "Direct Setup" mode (or any mode that relies on user-provided URLs).
    3. Attacker needs to trick the user into entering a malicious URL in the extension's popup for either "Actual Server Address" or "Live Server Address" (or both).
    4. Optionally, attacker controls a server at the "Actual Server Address" to serve malicious content.
* Source Code Analysis:
    - **`popup/popup.js`:** This file takes user input from `actualServerAddress` and `liveServerAddress` input fields and directly sends them to the background script without any validation in the `submitForm` function.
      ```javascript
      function submitForm() {
          const formData = {
              isEnable: liveReloadCheck.checked,
              proxySetup: !noProxyCheckBox.checked,
              actualUrl: actualServerAddress.value || '',
              liveServerUrl: liveServerAddress.value || ''
          }

          chrome.runtime.sendMessage({
              req: 'set-live-server-config',
              data: formData
          });
      }
      ```
    - **`background.js`:** This file receives the configuration data and stores it in `chrome.storage.local` without validation in `storeConfigToLocalStorage` function.
      ```javascript
      function storeConfigToLocalStorage(data) {
          // return promise
          return chrome.storage.local.set({ [SETUP_STRING]: data || {} })
      }
      ```
    - **`reload.js`:** This file retrieves the `liveServerUrl` from the configuration and uses it to create a WebSocket connection in the `init` function without any validation.
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

* Security Test Case:
    1. Set up a malicious WebSocket server (e.g., using `wscat -l 8080`). This server will simply send the message 'reload' to any connected client.
    2. Open the Live Server Web Extension popup.
    3. In the "Live Server Address" field, enter `http://localhost:8080`. (or `http://<attacker's-ip>:8080` if testing remotely).
    4. Ensure "No Proxy Setup" is checked.
    5. Click "Submit".
    6. Open any webpage in the browser.
    7. Observe that the webpage reloads continuously because the malicious WebSocket server is sending 'reload' messages and the extension is blindly following them.
    8. To further demonstrate the impact, set up a simple HTTP server (e.g., using Python's `http.server`) on port 80 of localhost that serves a webpage with a JavaScript alert:
       ```html
       <html>
       <head><title>Malicious Page</title></head>
       <body>
           <h1>Malicious Content</h1>
           <script>alert("You have been pwned by malicious live reload!");</script>
       </body>
       </html>
       ```
    9. In the Live Server Web Extension popup:
        - "Actual Server Address": `http://localhost`
        - "Live Server Address": `http://localhost:8080`
        - "No Proxy Setup": checked
    10. Click "Submit".
    11. In the browser, visit `http://localhost`.
    12. Observe that the "Malicious Page" is loaded and the JavaScript alert is executed. Because the WebSocket server at `localhost:8080` is sending 'reload' messages, if you make any file change in your VS Code project that VS Code Live Server is monitoring, the page at `http://localhost` will reload, and the malicious alert will reappear. This demonstrates how a malicious configuration can lead to persistent execution of attacker-controlled content due to the live reload mechanism.