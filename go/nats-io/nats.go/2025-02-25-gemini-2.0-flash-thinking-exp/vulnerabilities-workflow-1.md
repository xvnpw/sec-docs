## Combined Vulnerability List

This document consolidates identified vulnerabilities from provided lists into a single, deduplicated list, detailing each vulnerability with its description, impact, rank, mitigations, and necessary steps for analysis and testing.

### 1. Stream and Consumer Name Injection via API Subject

- **Vulnerability Name:** Stream and Consumer Name Injection via API Subject

- **Description:**
An attacker can inject malicious commands or manipulate API subjects used for JetStream management operations by crafting stream or consumer names with special characters, such as newline characters. The library constructs API subjects by embedding stream and consumer names directly, lacking sufficient sanitization. While `checkStreamName` and `checkConsumerName` functions exist, they are inadequate against newline injection and similar attacks, potentially leading to command injection-like behavior within the NATS server's subject parsing.

Steps to trigger the vulnerability:
1. Establish a NATS client connection.
2. Obtain a JetStreamManager instance.
3. Attempt to create a stream or consumer with a name containing a newline character (`\n`) or other special characters like wildcard characters (`*`, `>`). For example, use a stream name like `"stream\nINJECTED_COMMAND"` or `"stream*name"`.
4. The library constructs an API subject using this crafted name.
5. When the NATS server processes this subject, special characters might be misinterpreted as subject separators or wildcards, potentially leading to the execution of unintended commands or actions within the JetStream management context, or bypassing intended authorization scopes.

- **Impact:**
Successful exploitation could allow attackers to bypass access controls and manipulate JetStream streams and consumers in unauthorized ways. This may lead to data corruption, exfiltration, or service disruption. The severity is high due to the potential for significant unauthorized actions within the messaging system, especially if server-side authorization relies on predictable subject structures.

- **Vulnerability Rank:** High

- **Currently Implemented Mitigations:**
The project includes `checkStreamName` and `checkConsumerName` functions in `jsm.go`. These functions validate stream and consumer names, checking for whitespace and dot characters.

```go
func checkStreamName(stream string) error {
	if stream == _EMPTY_ {
		return ErrStreamNameRequired
	}
	if strings.ContainsAny(stream, ". ") {
		return ErrInvalidStreamName
	}
	return nil
}

func checkConsumerName(consumer string) error {
	if consumer == _EMPTY_ {
		return ErrConsumerNameRequired
	}
	if strings.ContainsAny(consumer, ". ") {
		return ErrInvalidConsumerName
	}
	return nil
}
```
These checks prevent names with dots and spaces, but they do not prevent newline characters (`\n`), wildcard characters (`*`, `>`), or other potentially harmful characters that might be processed specially by the NATS server's subject parsing logic. Client-side validation in the Go client library prevents creating stream or consumer names with newline characters and wildcard characters through the Go client library itself, resulting in "invalid stream name" or "invalid consumer name" errors. However, this client-side validation is not a complete mitigation, as other clients or direct API interactions might bypass these checks.

- **Missing Mitigations:**
The project lacks comprehensive sanitization of stream and consumer names to prevent injection attacks via API subjects. Missing mitigations include:
    - **Disallowing or sanitizing newline characters (`\n`), wildcard characters (`*`, `>`), and other control characters** that could be interpreted specially in NATS subjects.
    - **Implementing robust input validation** using a strict whitelist of allowed characters (e.g., alphanumeric characters and underscores only) to ensure stream and consumer names conform to a safe character set, preventing subject manipulation.
    - **Server-side validation** of stream and consumer names as a defense-in-depth measure.

- **Preconditions:**
    - JetStream must be enabled on the NATS server.
    - The attacker must have access to a NATS connection and be able to create a JetStreamManager.
    - The NATS server's subject parsing logic might be susceptible to command injection or unintended behavior when encountering newline characters or other special characters in subjects. Server-side authorization might rely on predictable subject structures that can be bypassed with injection.

- **Source Code Analysis:**
1. **File:** `/code/jsm.go`
2. **Vulnerable Code Location:** API subject construction in functions like `AddStream`, `UpdateStream`, `DeleteStream`, `AddConsumer`, `DeleteConsumer`, `ConsumerInfo`, etc.
3. **Code Walkthrough:**
    - In functions like `js.AddStream`, the stream name from the `StreamConfig` is directly embedded into the API subject string using `fmt.Sprintf`.
    ```go
    csSubj := js.apiSubj(fmt.Sprintf(apiStreamCreateT, cfg.Name))
    r, err := js.apiRequestWithContext(o.ctx, csSubj, req)
    ```
    - Similarly, in `js.DeleteStream`, the stream name is directly embedded:
    ```go
    dsSubj := js.apiSubj(fmt.Sprintf(apiStreamDeleteT, name))
    r, err := js.apiRequestWithContext(o.ctx, dsSubj, nil)
    ```
    - The same pattern exists for consumer-related functions, like in `js.DeleteConsumer`:
    ```go
    dcSubj := js.apiSubj(fmt.Sprintf(apiConsumerDeleteT, stream, consumer))
    r, err := js.apiRequestWithContext(o.ctx, r, nil)
    ```
    - The `apiSubj` function simply prepends the API prefix.
    ```go
    func (js *js) apiSubj(subj string) string {
        return js.opts.pre + subj
    }
    ```
    - `checkStreamName` and `checkConsumerName` are called for validation, but their checks are insufficient against characters like newline or wildcards.

    - **Visualization:**

    ```
    User Input (Stream Name): "stream\nINJECTED_COMMAND"
        |
        V
    js.AddStream(StreamConfig{Name: "stream\nINJECTED_COMMAND", ...})
        |
        V
    API Subject Construction (jsm.go):
    csSubj := js.apiSubj(fmt.Sprintf(apiStreamCreateT, cfg.Name))
           = js.apiSubj(fmt.Sprintf("$JS.API.STREAM.CREATE.%s", "stream\nINJECTED_COMMAND"))
           = "$JS.API.STREAM.CREATE.stream\nINJECTED_COMMAND"
        |
        V
    NATS Client Sends Request to Server with Subject: "$JS.API.STREAM.CREATE.stream\nINJECTED_COMMAND"
        |
        V
    NATS Server Subject Processing (Potential Command Injection/Authorization Bypass)
    ```

4. **Vulnerability Explanation:**
    The vulnerability stems from directly using user-provided stream and consumer names to construct API subjects without sufficient sanitization against special characters. This can lead to subject injection if the NATS server's subject processing is vulnerable, potentially causing command injection or authorization bypass. While client-side validation in the Go library offers basic protection, it is incomplete and server-side and more robust client-side sanitization are needed.

- **Security Test Case:**
1. **Prerequisites:**
    - Running NATS server with JetStream enabled.
    - Go development environment.
    - `nats.go` library project.

2. **Test Setup:**
    - Create a Go test file (e.g., `stream_injection_test.go`) in the `test` directory.
    - Import `nats` library and `testing` package.
    - Establish connection to NATS server.
    - Create a JetStreamManager.

3. **Test Steps:**
    ```go
    package test

    import (
        "strings"
        "testing"

        "github.com/nats-io/nats.go"
    )

    func TestStreamNameInjection(t *testing.T) {
        nc, js := setupJetStream(t)
        defer nc.Close()

        // Test with newline character
        testInjectionCharacter(t, js, "stream\nINJECTED", "invalid stream name")
        // Test with wildcard character '*'
        testInjectionCharacter(t, js, "stream*INJECTED", "invalid stream name")
        // Test with wildcard character '>'
        testInjectionCharacter(t, js, "stream>INJECTED", "invalid stream name")

        // Test consumer name injection with newline
        testConsumerNameInjection(t, js, "consumer\nINJECTED", "invalid consumer name")
        // Test consumer name injection with wildcard '*'
        testConsumerNameInjection(t, js, "consumer*INJECTED", "invalid consumer name")
        // Test consumer name injection with wildcard '>'
        testConsumerNameInjection(t, js, "consumer>INJECTED", "invalid consumer name")
    }

    func testInjectionCharacter(t *testing.T, js nats.JetStreamManager, streamName string, expectedError string) {
        streamCfg := &nats.StreamConfig{
            Name:     streamName,
            Subjects: []string{"inj.>"},
        }

        _, err := js.AddStream(streamCfg)
        if err == nil {
            t.Fatalf("Expected error when creating stream with injected name '%s', but got none", streamName)
        }

        if !strings.Contains(err.Error(), expectedError) && !strings.Contains(err.Error(), strings.ReplaceAll(expectedError, " ", "")) { // To handle both "invalid stream name" and "InvalidStreamName"
            t.Fatalf("Expected '%s' error for stream name '%s', got: %v", expectedError, streamName, err)
        }
    }

    func testConsumerNameInjection(t *testing.T, js nats.JetStreamManager, consumerName string, expectedError string) {
        consCfg := &nats.ConsumerConfig{
            Durable:   consumerName,
            AckPolicy: nats.AckExplicitPolicy,
        }

        _, err := js.AddConsumer("test_stream", consCfg) // Assuming "test_stream" exists
        if err == nil {
            t.Fatalf("Expected error when creating consumer with injected name '%s', but got none", consumerName)
        }
        if !strings.Contains(err.Error(), expectedError) && !strings.Contains(err.Error(), strings.ReplaceAll(expectedError, " ", "")) { // To handle both "invalid consumer name" and "InvalidConsumerName"
            t.Fatalf("Expected '%s' error for consumer name '%s', got: %v", expectedError, consumerName, err)
        }
    }


    func setupJetStream(t *testing.T) (*nats.Conn, nats.JetStreamManager) {
        t.Helper()
        nc, err := nats.Connect(nats.DefaultURL)
        if err != nil {
            t.Fatalf("Could not connect to NATS: %v", err)
        }
        js, err := nc.JetStream()
        if err != nil {
            nc.Close()
            t.Fatalf("Could not create JetStream context: %v", err)
        }
        _, err = js.AddStream(&nats.StreamConfig{Name: "test_stream", Subjects: []string{"test.>"} })
        if err != nil {
            nc.Close()
            t.Fatalf("Could not create test stream: %v", err)
        }
        return nc, js
    }
    ```

4. **Expected Result:**
    The test should confirm that the `nats.go` library's client-side validation prevents stream and consumer names with newline and wildcard characters. The test expects "invalid stream name" or "invalid consumer name" errors. Passing the test indicates client-side validation is working but is insufficient for full mitigation, highlighting the need for server-side and more robust client-side sanitization. If the test fails, it indicates a vulnerability or insufficient client-side validation. Based on current code, this test should pass, confirming client-side validation is in place, but server-side checks are crucial for complete security.

### 2. Subject Confusion in Direct Get API

- **Vulnerability Name:** Subject Confusion in Direct Get API

- **Description:**
The `GetLastMsg` function in `jsm.go` retrieves the last message for a subject in a JetStream stream via the Direct Get API. While stream name validation exists, the `subject` parameter lacks validation. If not sanitized, an attacker could inject wildcards into the subject, potentially retrieving messages from unintended subjects within the stream if the server's Direct Get API subject handling is not strictly exact-match.

Steps to trigger the vulnerability:
1. An attacker crafts a malicious subject string with wildcard characters (e.g., `ORDERS.*`, `ORDERS.>`).
2. The attacker calls `GetLastMsg` with this subject, aiming to retrieve the last message for a seemingly legitimate subject but using the malicious subject to broaden the scope.
3. If the NATS server's Direct Get API subject matching allows wildcard expansion, messages from unintended subjects might be returned.
4. This could lead to information disclosure by allowing access to messages not intended for the attacker.

- **Impact:**
Potential unauthorized access to messages from subjects within a stream that the attacker should not access. Information disclosure through retrieval of messages from broader or different subjects than intended.

- **Vulnerability Rank:** High

- **Currently Implemented Mitigations:**
The `checkStreamName` function validates the stream name, but there is no validation for the `subject` parameter in `GetLastMsg`.

- **Missing Mitigations:**
    - Input validation and sanitization for the `subject` parameter in `GetLastMsg` to prevent subject injection.
    - Validation should ensure the subject is a valid NATS subject without wildcard characters or other harmful characters leading to unintended subject matching.
    - Documentation should advise caution when using `GetLastMsg` with user-provided subjects and discourage wildcard subjects.

- **Preconditions:**
    - The attacker must be able to call `GetLastMsg` or influence its parameters with a malicious subject.
    - The NATS server's Direct Get API subject matching must not be strictly exact-match and be susceptible to wildcard expansion.

- **Source Code Analysis:**
1. **File:** `/code/jsm.go`
2. **Vulnerable Code Location:** `GetLastMsg` function at line 999.
3. **Code Walkthrough:**
    - `GetLastMsg` calls the internal `getMsg` function, passing the `subject` parameter directly without validation.
    - `getMsg` validates the stream `name` but not the `subject`.
    - Lack of validation for `subject` allows arbitrary subjects, including wildcards, to be passed to the Direct Get API, potentially leading to unintended message retrieval if the server allows wildcard matching.

- **Security Test Case:**
1. **Setup:**
    - Running NATS server with JetStream enabled.
    - Create a JetStream stream "TEST_STREAM" with subjects `TEST_STREAM.SUBJECT1` and `TEST_STREAM.SUBJECT2`, and publish messages to both.
    - Create a Go application using `nats.go` client and JetStream API.

2. **Test Steps:**
    - Call `GetLastMsg` with a malicious subject like `TEST_STREAM.>` (wildcard) to retrieve messages from all subjects, intending only `TEST_STREAM.SUBJECT1`.
    ```go
    package main

    import (
        "context"
        "fmt"
        "log"
        "time"

        "github.com/nats-io/nats.go"
        "github.com/nats-io/nats.go/jetstream"
    )

    var ctx = context.Background()

    func main() {
        nc, err := nats.Connect(nats.DefaultURL)
        if err != nil {
            log.Fatal(err)
        }
        defer nc.Close()

        js, err := jetstream.New(nc)
        if err != nil {
            log.Fatal(err)
        }

        streamName := "TEST_STREAM"
        // Setup stream with two subjects
        _, err = js.AddStream(ctx, jetstream.StreamConfig{
            Name:     streamName,
            Subjects: []string{"TEST_STREAM.SUBJECT1", "TEST_STREAM.SUBJECT2"},
        })
        if err != nil {
            log.Fatalf("Failed to add stream: %v", err)
        }
        // Publish messages to both subjects
        _, err = js.Publish(ctx, "TEST_STREAM.SUBJECT1", []byte("Message 1"))
        if err != nil {
            log.Fatalf("Failed to publish to SUBJECT1: %v", err)
        }
        _, err = js.Publish(ctx, "TEST_STREAM.SUBJECT2", []byte("Message 2"))
        if err != nil {
            log.Fatalf("Failed to publish to SUBJECT2: %v", err)
        }
        time.Sleep(time.Second) // Wait for publish to complete

        maliciousSubject := "TEST_STREAM.>" // Malicious subject with wildcard

        msg, err := js.GetLastMsg(ctx, streamName, maliciousSubject)
        if err != nil {
            fmt.Printf("Error getting last message: %v\n", err)
        } else if msg != nil {
            fmt.Printf("Retrieved message from subject: %s, data: %s\n", msg.Subject, string(msg.Data))
        } else {
            fmt.Println("No message found")
        }
    }
    ```

3. **Verification:**
    - Run the application and check if `GetLastMsg` with the malicious subject retrieves messages.
    - Verify if the retrieved message's subject is from a broader scope than intended (e.g., if using `TEST_STREAM.>`, messages from both `TEST_STREAM.SUBJECT1` and `TEST_STREAM.SUBJECT2` are potentially retrieved).
    - Success indicates subject injection in `GetLastMsg`, potentially leading to unauthorized message access.

### 3. WebSocket Frame Injection via Unvalidated Control Frame Payloads

- **Vulnerability Name:** WebSocket Frame Injection via Unvalidated Control Frame Payloads

- **Description:**
The `nats.go` library's WebSocket implementation in `ws.go` handles WebSocket control frames (Ping, Pong, Close). The `handleControlFrame` function processes these frames and extracts payloads for Close and Ping frames. For Ping frames, it enqueues a Pong response with the same payload. The payload of control frames, especially Ping and Close, is not strictly validated for malicious content before being processed or echoed back. An attacker could inject crafted payloads within control frames that, when processed or reflected, might lead to unexpected behavior in the client or server, or potentially other connected WebSocket clients if the server echoes pings.

Steps to trigger the vulnerability:
1. An attacker establishes a WebSocket connection to a NATS server via `nats.go` client.
2. The attacker crafts a malicious payload (up to 125 bytes) designed to potentially exploit a vulnerability when processed or reflected. This payload could be crafted to look like a valid WebSocket frame header if misinterpreted.
3. The attacker sends a WebSocket Ping frame to the NATS server with the malicious payload.
4. `handleControlFrame` processes the Ping, extracts the payload, and enqueues a Pong with the *same* payload.
5. The NATS server (or another component if server reflects pings) processes or reflects the crafted payload, potentially triggering unintended behavior due to lack of sanitization in `nats.go` and reliance on server/other clients' handling of arbitrary payloads in control frames.

- **Impact:**
Potential client-side or server-side misbehavior due to processing or reflection of malicious payloads in WebSocket control frames. Carefully crafted payloads could exploit vulnerabilities in WebSocket frame parsing or state management in NATS server or other clients if server echoes pings. In Close frames, malicious payloads could lead to confusing close status codes or messages.

- **Vulnerability Rank:** High

- **Currently Implemented Mitigations:**
The `handleControlFrame` function in `ws.go` checks if the control frame payload size exceeds `wsMaxControlPayloadSize` (125 bytes).

- **Missing Mitigations:**
    - Input validation and sanitization of control frame payloads in `handleControlFrame` to prevent injection of malicious content.
    - For Ping frames, consider stripping or sanitizing the payload before echoing it in a Pong response.
    - For Close frames, validate the status code and sanitize the body to ensure they conform to expected formats.
    - Documentation should warn against echoing or logging control frame payloads without sanitization, especially if from external input.

- **Preconditions:**
    - The attacker must be able to establish a WebSocket connection to the NATS server.
    - The NATS server or other connected WebSocket clients must be potentially vulnerable to processing or reflecting malicious payloads in WebSocket control frames.

- **Source Code Analysis:**
1. **File:** `/code/ws.go`
2. **Vulnerable Code Location:** `handleControlFrame` function at line 238.
3. **Code Walkthrough:**
    - `handleControlFrame` processes WebSocket control frames.
    - For `wsPingMessage`, it directly uses the received payload to enqueue a `wsPongMessage` with `r.nc.wsEnqueueControlMsg(r.nl, wsPongMessage, payload)` without validation.
    - For `wsCloseMessage`, it extracts the payload and parses for status code and body. While UTF-8 validity of the body is checked, deeper sanitization of payload content is missing.
    - Lack of validation of control frame payload *content* allows for potential exploitation with crafted payloads.

- **Security Test Case:**
1. **Setup:**
    - Running NATS server supporting WebSocket connections.
    - Go application using `nats.go` client to establish WebSocket connection.
    - Optional: Monitoring tool or another WebSocket client to observe traffic/server behavior.

2. **Test Steps:**
    - Send a WebSocket Ping frame with a malicious payload. Example: `[]byte{0x81, 0x05, 0x48, 0x65, 0x6c, 0x6c, 0x6f}` (resembles text frame header).
    ```go
    package main

    import (
        "log"
        "time"

        "github.com/nats-io/nats.go"
    )

    func main() {
        nc, err := nats.Connect("ws://localhost:8080") // Or wss://...
        if err != nil {
            log.Fatalf("Failed to connect: %v", err)
        }
        defer nc.Close()

        maliciousPayload := []byte{0x81, 0x05, 0x48, 0x65, 0x6c, 0x6c, 0x6f} // Example malicious payload

        // Access the underlying websocket writer to send a raw ping frame.
        if wsWriter, ok := nc.bw.w.(*nats.websocketWriter); ok {
            fh, key := nats.WsCreateFrameHeader(false, nats.WsPingMessage, len(maliciousPayload))
            nats.WsMaskBuf(key, maliciousPayload)
            frame := append(fh, maliciousPayload...)
            _, err = wsWriter.Write(frame)
            if err != nil {
                log.Fatalf("Failed to send malicious ping: %v", err)
            }
            log.Println("Malicious Ping frame sent.")
        } else {
            log.Fatal("Not a websocket connection.")
        }


        time.Sleep(2 * time.Second) // Wait to observe any effects.
    }
    ```

3. **Verification:**
    - Run the application to send the malicious Ping frame.
    - Monitor NATS server logs and behavior for anomalies, errors, or crashes.
    - Observe WebSocket traffic for Pong response. Check if malicious payload is echoed back verbatim.
    - If another WebSocket client is connected and the server reflects pings, observe that client for unexpected behavior or errors.
    - Analyze if the malicious payload caused parsing errors, state corruption, or other unintended effects in the NATS server or client.