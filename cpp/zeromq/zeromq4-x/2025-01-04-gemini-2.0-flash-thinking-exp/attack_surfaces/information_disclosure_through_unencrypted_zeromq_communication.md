```python
# This is a conceptual code snippet to illustrate CurveZMQ implementation,
# not a fully functional application.

import zmq

# --- Server Side Example ---
def start_secure_zmq_server(bind_address="tcp://*:5555"):
    """Starts a ZeroMQ server with CurveZMQ encryption."""
    ctx = zmq.Context()
    server_socket = ctx.socket(zmq.REP)

    # Generate server key pair
    server_public_key, server_secret_key = zmq.curve_keypair()

    # Apply the keys to the server socket
    server_socket.curve_publickey = server_public_key
    server_socket.curve_secretkey = server_secret_key

    server_socket.bind(bind_address)
    print(f"Secure ZeroMQ server listening on {bind_address}")
    return server_socket, server_public_key

# --- Client Side Example ---
def connect_secure_zmq_client(connect_address="tcp://localhost:5555", server_public_key=None):
    """Connects a ZeroMQ client with CurveZMQ encryption."""
    if not server_public_key:
        raise ValueError("Server public key is required for secure connection.")

    ctx = zmq.Context()
    client_socket = ctx.socket(zmq.REQ)

    # Generate client key pair
    client_public_key, client_secret_key = zmq.curve_keypair()

    # Apply the keys and the server's public key to the client socket
    client_socket.curve_publickey = client_public_key
    client_socket.curve_secretkey = client_secret_key
    client_socket.curve_serverkey = server_public_key

    client_socket.connect(connect_address)
    print(f"Secure ZeroMQ client connected to {connect_address}")
    return client_socket

if __name__ == "__main__":
    # Example Usage (Conceptual)

    # Start the secure server
    server_socket, server_public = start_secure_zmq_server()

    # Simulate secure key exchange (in a real application, this would be out-of-band)
    # For demonstration, we are passing the server's public key directly.
    # In production, use a secure method like a configuration file over HTTPS,
    # a secrets management system, or a secure key exchange protocol.

    # Connect the secure client
    client_socket = connect_secure_zmq_client(server_public_key=server_public)

    # Send and receive messages securely
    message = b"Sensitive data to be transmitted securely"
    client_socket.send(message)
    reply = server_socket.recv()
    print(f"Client sent: {message.decode()}")
    print(f"Server received: {reply.decode()}")

    # Clean up
    server_socket.close()
    client_socket.close()
    zmq.Context.instance().term()
```