## Vulnerability List

### Configuration Injection leading to Uncontrolled Page Reloads

* Description:
    1. An attacker cannot directly inject malicious configurations into the extension's storage.
    2. However, an attacker can socially engineer a user to manually configure the "Live Server Web Extension" with a malicious "Live Server Address" in the extension's popup settings. This could be achieved through phishing or by misleading the user on forums or documentation.
    3. If a user is tricked into setting the "Live Server Address" to a URL controlled by the attacker (e.g., `ws://attacker.com/ws`), the extension will establish a WebSocket connection to the attacker's server.
    4. The `reload.js` script listens for WebSocket messages. If the attacker's server sends a message with the data 'reload' or 'refreshcss', the `reloadWindow` function in `reload.js` will trigger a page reload.
    5. Because the attacker controls the WebSocket server, they can send arbitrary 'reload' or 'refreshcss' messages at any time, causing the user's browser to reload pages unexpectedly and potentially disrupting the user's workflow.
    6. The vulnerability is triggered when the extension is enabled (`isEnable: true`) and the user is browsing any webpage. The page reload will happen if the attacker sends the specific messages via the WebSocket connection.

* Impact:
    - Unwanted and continuous page reloads, disrupting the user's browsing experience and workflow.
    - Potential for annoyance and frustration, making the extension unusable.
    - While not a direct security breach like data theft, it can be used to persistently harass or disrupt a targeted user's browsing activity, especially if they rely on the "Live Server Web Extension".

* Vulnerability Rank: High

* Currently implemented mitigations:
    - None. The extension functions as designed by connecting to the configured WebSocket URL and reloading on specific messages.

* Missing mitigations:
    - Input validation and sanitization for the "Live Server Address" in `popup/popup.js`. The extension should warn users about connecting to untrusted WebSocket servers and potentially validate the format of the URL.
    - Origin validation for WebSocket messages in `reload.js`. While the messages themselves are simple strings ('reload', 'refreshcss'), validating the WebSocket origin could add a layer of defense, although it might be complex to implement in this extension context.
    - Clearer security warnings in the extension's UI and documentation about the risks of using untrusted "Live Server Addresses".

* Preconditions:
    - User must have the "Live Server Web Extension" installed.
    - User must be socially engineered into manually configuring the extension with a malicious "Live Server Address" in the popup settings.
    - The "Live Reload" feature must be enabled in the extension's popup (`liveReloadCheck.checked = true`).

* Source code analysis:
    1. **`popup/popup.js`**:
        - User inputs "Live Server Address" into `liveServerAddress` input field.
        - In `submitForm` function, `liveServerAddress.value` is directly taken and stored in `formData.liveServerUrl` without any validation or sanitization.
        - `formData` is sent to `background.js` via `chrome.runtime.sendMessage`.
    2. **`background.js`**:
        - `chrome.runtime.onMessage` listener handles messages.
        - When `msg.req === 'set-live-server-config'`, the `msg.data` (which includes `liveServerUrl`) is directly stored in `chrome.storage.local` using `storeConfigToLocalStorage`.
    3. **`reload.js`**:
        - On initialization, `getConfigFromLocalStorage` fetches the configuration including `liveServerUrl` from `chrome.storage.local`.
        - `address = data.liveServerUrl.replace('http', 'ws') + '/ws';` constructs the WebSocket URL using the user-provided `liveServerUrl`. No validation is performed on `data.liveServerUrl` before using it to create a WebSocket connection.
        - `socket = new WebSocket(address);` establishes the WebSocket connection to the potentially attacker-controlled address.
        - `socket.onmessage = (msg) => { reloadWindow(msg, data) };` sets up a message handler.
        - `reloadWindow` function checks `msg.data`. If it is 'reload' or 'refreshcss', and the conditions related to `proxySetup` and `actualUrl` are met (or if `proxySetup` is true), `window.location.reload()` is called, triggering a page reload.

    ```
    popup/popup.js --> background.js (storeConfigToLocalStorage) --> chrome.storage.local --> background.js (getConfigFromLocalStorage) --> reload.js --> WebSocket connection to user-provided URL --> reload on attacker message
    ```

* Security test case:
    1. **Setup Attacker Server:**
        - Set up a simple WebSocket server (e.g., using Node.js and `ws` library) on `attacker.com` (or a local machine for testing).
        - The server should be able to accept WebSocket connections and send messages.
        - The server should send the message `'reload'` or `'refreshcss'` after a connection is established.
    2. **Victim Configuration:**
        - Install the "Live Server Web Extension" in Chrome or Firefox.
        - Open the extension's popup by clicking on its icon.
        - Enable "Live Reload" checkbox.
        - Ensure "No Proxy Setup" checkbox is checked (to make "Live Server Address" field visible).
        - In the "Live Server Address" field, enter `http://attacker.com` (or `ws://attacker.com` if your server is on `ws` protocol, ensure protocol consistency).
        - Click "Submit".
    3. **Victim Browsing:**
        - Open any website in the browser.
    4. **Trigger Attack:**
        - Ensure the attacker's WebSocket server is running and accepting connections.
        - The "Live Server Web Extension" in the victim's browser should establish a WebSocket connection to `attacker.com`.
        - The attacker's server sends the message `'reload'` to the connected WebSocket client (the extension).
    5. **Verify Vulnerability:**
        - Observe that the webpage in the victim's browser reloads unexpectedly upon receiving the `'reload'` message from the attacker's server.
        - The attacker can repeat step 4 to trigger continuous reloads as long as the WebSocket connection is active and the extension is enabled.