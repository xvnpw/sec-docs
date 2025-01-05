```python
# This is a conceptual example and not directly executable.
# It illustrates the principles discussed in the analysis.

import json
import time
import uuid
from collections import deque

# --- Server-Side (Illustrative) ---

class WebSocketServer:
    def __init__(self):
        self.processed_nonces = set()
        self.session_states = {} # Example: {session_id: {'last_seq': 0}}

    def handle_message(self, client_id, message_str):
        try:
            message = json.loads(message_str)
            if not isinstance(message, dict):
                print(f"Invalid message format from {client_id}")
                return

            # --- Mitigation Strategies ---

            # 1. Nonce Validation
            nonce = message.get("nonce")
            if not nonce or nonce in self.processed_nonces:
                print(f"Replayed or invalid nonce from {client_id}")
                return
            self.processed_nonces.add(nonce)
            # Consider a time-based eviction policy for processed_nonces

            # 2. Timestamp Validation
            timestamp = message.get("timestamp")
            if not timestamp or abs(time.time() - timestamp) > 60: # Example: 60-second window
                print(f"Stale timestamp from {client_id}")
                return

            # 3. Authorization Check (Example - depends on your auth mechanism)
            action = message.get("action")
            if not self.is_authorized(client_id, action):
                print(f"Unauthorized action '{action}' from {client_id}")
                return

            # 4. Session State and Sequence Numbers (Illustrative)
            session_id = self.get_session_id(client_id) # Assuming a way to get session ID
            seq_num = message.get("sequence_number")
            if session_id:
                if session_id not in self.session_states:
                    self.session_states[session_id] = {'last_seq': 0}
                expected_seq = self.session_states[session_id]['last_seq'] + 1
                if seq_num != expected_seq:
                    print(f"Out-of-order or replayed message (sequence) from {client_id}")
                    return
                self.session_states[session_id]['last_seq'] = seq_num

            # --- Process the legitimate message ---
            self.process_action(client_id, message)

        except json.JSONDecodeError:
            print(f"Error decoding JSON from {client_id}")

    def is_authorized(self, client_id, action):
        # Implement your authorization logic here
        # This is a placeholder
        return True

    def process_action(self, client_id, message):
        action = message.get("action")
        data = message.get("data")
        print(f"Processing action '{action}' from {client_id} with data: {data}")
        # Perform the actual action based on the message

    def get_session_id(self, client_id):
        # Implement logic to retrieve the session ID associated with the client
        # This could involve looking up a mapping based on the client connection
        return "some_session_id" # Placeholder

# --- Client-Side (Illustrative) ---

class WebSocketClient:
    def __init__(self):
        self.sequence_number = 0

    def create_message(self, action, data):
        self.sequence_number += 1
        return json.dumps({
            "action": action,
            "data": data,
            "nonce": str(uuid.uuid4()),
            "timestamp": time.time(),
            "sequence_number": self.sequence_number
        })

# --- Example Usage ---

server = WebSocketServer()
client1 = WebSocketClient()

# Legitimate message
msg1 = client1.create_message("transfer_funds", {"amount": 100, "to": "userB"})
server.handle_message("client1", msg1)

# Attacker captures msg1

# Attacker replays msg1
server.handle_message("attacker_pretending_as_client1", msg1) # Will likely be blocked by nonce

# Create a new legitimate message
msg2 = client1.create_message("update_profile", {"name": "New Name"})
server.handle_message("client1", msg2)
```

**Detailed Explanation of the Code Example:**

1. **Server-Side (`WebSocketServer`):**
    *   **`processed_nonces`:** A set to store nonces of processed messages. This helps detect replay attacks by checking if a nonce has been used before. A time-based eviction policy would be crucial in a real-world scenario to prevent this set from growing indefinitely.
    *   **`session_states`:** A dictionary to store session-specific information, including the last processed sequence number. This helps detect out-of-order or replayed messages within a session.
    *   **`handle_message(client_id, message_str)`:** This function simulates the server's message processing logic. It includes checks for:
        *   **Nonce Validation:**  Checks if the `nonce` in the incoming message is present and hasn't been seen before.
        *   **Timestamp Validation:** Checks if the `timestamp` in the message is within a reasonable time window.
        *   **Authorization Check:** A placeholder function (`is_authorized`) to simulate checking if the user is authorized to perform the requested action.
        *   **Sequence Number Validation:** Checks if the `sequence_number` in the message is the expected next number in the session.
    *   **`is_authorized(client_id, action)`:** A placeholder for your actual authorization logic.
    *   **`process_action(client_id, message)`:**  Simulates the actual processing of a legitimate message.
    *   **`get_session_id(client_id)`:** A placeholder for how you would retrieve the session ID associated with a client connection.

2. **Client-Side (`WebSocketClient`):**
    *   **`sequence_number`:**  Keeps track of the message sequence number for the client.
    *   **`create_message(action, data)`:**  Generates a WebSocket message with:
        *   `action`: The action to be performed.
        *   `data`:  The data associated with the action.
        *   `nonce`: A unique identifier generated using `uuid.uuid4()`.
        *   `timestamp`: The current time.
        *   `sequence_number`: The incremented sequence number.

3. **Example Usage:**
    *   Demonstrates sending a legitimate message and then simulating a replay attack. The server's `handle_message` function would (ideally) detect the replayed message due to the nonce check.
    *   Shows how a subsequent legitimate message would be processed.

**Key Takeaways from the Code Example:**

*   **Illustrates Mitigation Strategies:** The code directly demonstrates the implementation of nonce validation, timestamp validation, and sequence number checking.
*   **Highlights the Importance of Application Logic:** The security against replay attacks is primarily implemented within the server's message handling logic.
*   **Conceptual Nature:** This is a simplified example. Real-world implementations would require more robust error handling, session management, and potentially more sophisticated authorization mechanisms.
*   **`gorilla/websocket` Context:** While the example doesn't directly use `gorilla/websocket`'s API, it represents the logic that would be applied *within* the message handling functions you define when using `gorilla/websocket` to receive and process messages.

**Integrating with `gorilla/websocket`:**

In a real application using `gorilla/websocket`, you would integrate these mitigation strategies within your WebSocket handler functions. For example:

```python
from gorilla import websocket
import json
import time
import uuid
from collections import deque

# ... (WebSocketServer class as defined above)

def handler(ws: websocket.Conn, server: WebSocketServer):
    while True:
        mt, message = ws.ReadMessage()
        if mt == websocket.TextMessage:
            server.handle_message(ws.RemoteAddr().String(), message.decode('utf-8'))
        elif mt == websocket.CloseMessage:
            break
        elif mt == websocket.BinaryMessage:
            # Handle binary messages if needed
            pass

# ... (Setting up the WebSocket server using gorilla/websocket)
```

In this scenario, the `handler` function receives messages from the WebSocket connection, and the `server.handle_message` function (which implements the replay attack mitigations) is called to process the incoming message.

By implementing these checks, your application can effectively defend against message replay attacks, ensuring the integrity and security of your WebSocket communication built with `gorilla/websocket`. Remember that a layered security approach is always recommended, and these mitigations should be part of a broader security strategy.
