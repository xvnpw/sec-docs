```python
# This is a conceptual Python example to demonstrate how one might test for the presence of the vulnerability.
# It is not a comprehensive security testing tool and should be used with caution in controlled environments.

import socket
import ssl

def check_unencrypted_connection(host, port=5672):
    """Attempts to connect to the RabbitMQ server on the standard unencrypted port."""
    try:
        with socket.create_connection((host, port), timeout=5) as sock:
            print(f"[!] WARNING: Successfully connected to {host}:{port} (unencrypted).")
            return True
    except ConnectionRefusedError:
        print(f"[+] INFO: Connection to {host}:{port} refused (expected if TLS is enforced).")
        return False
    except TimeoutError:
        print(f"[!] WARNING: Connection to {host}:{port} timed out. Could indicate a firewall or network issue.")
        return None
    except Exception as e:
        print(f"[!] ERROR: An unexpected error occurred while connecting to {host}:{port}: {e}")
        return None

def check_tls_connection(host, port=5671):
    """Attempts to establish a TLS connection to the RabbitMQ server."""
    context = ssl.create_default_context()
    try:
        with socket.create_connection((host, port), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                print(f"[+] INFO: Successfully established TLS connection to {host}:{port}.")
                return True
    except ConnectionRefusedError:
        print(f"[!] WARNING: Connection to {host}:{port} refused. TLS might not be configured or a firewall is blocking.")
        return False
    except TimeoutError:
        print(f"[!] WARNING: TLS connection to {host}:{port} timed out. Could indicate a firewall or network issue.")
        return None
    except ssl.SSLError as e:
        print(f"[!] WARNING: SSL/TLS error while connecting to {host}:{port}: {e}")
        return False
    except Exception as e:
        print(f"[!] ERROR: An unexpected error occurred while connecting to {host}:{port} via TLS: {e}")
        return None

if __name__ == "__main__":
    rabbitmq_host = "your_rabbitmq_host" # Replace with the actual hostname or IP address

    print(f"[*] Checking for unencrypted connection on {rabbitmq_host}:5672...")
    unencrypted_vulnerable = check_unencrypted_connection(rabbitmq_host)

    print(f"[*] Checking for TLS connection on {rabbitmq_host}:5671...")
    tls_enabled = check_tls_connection(rabbitmq_host)

    print("\n--- Summary ---")
    if unencrypted_vulnerable is True:
        print("[!] CRITICAL: Unencrypted connections are possible. This vulnerability needs immediate attention.")
    elif unencrypted_vulnerable is False:
        print("[+] INFO: Unencrypted connections appear to be blocked or refused.")
    elif unencrypted_vulnerable is None:
        print("[!] WARNING: Unable to definitively determine the status of unencrypted connections.")

    if tls_enabled is True:
        print("[+] INFO: TLS connections are possible.")
    elif tls_enabled is False:
        print("[!] CRITICAL: TLS connections are not possible. Encryption is not configured correctly.")
    elif tls_enabled is None:
        print("[!] WARNING: Unable to definitively determine the status of TLS connections.")

    if unencrypted_vulnerable is True and tls_enabled is not True:
        print("[!!!] MAJOR SECURITY RISK: Unencrypted connections are possible, and TLS is either not enabled or failing. This is a high-priority issue.")
    elif unencrypted_vulnerable is True and tls_enabled is True:
        print("[!] WARNING: While TLS is enabled, the possibility of unencrypted connections still exists. Ensure TLS is enforced and unencrypted ports are blocked.")

```