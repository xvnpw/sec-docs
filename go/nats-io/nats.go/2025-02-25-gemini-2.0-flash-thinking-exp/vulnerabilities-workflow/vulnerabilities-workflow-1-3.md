## Vulnerability Report for NATS Go Client

**CURRENT_VULNERABILITIES:**

### Vulnerability 1: Stream and Consumer Name Injection

* Vulnerability Name: Stream and Consumer Name Injection
* Description:
    * The `nats.go` library allows users to create JetStream streams and consumers with names provided as input.
    * The `checkStreamName` and `checkConsumerName` functions in `jsm.go` validate these names, but the validation is insufficient.
    * Specifically, while these functions prevent whitespace and "." characters, they do not prevent other potentially harmful characters in stream and consumer names, especially when these names are used in API subject construction.
    * An attacker could potentially inject special characters into stream or consumer names that are not properly sanitized when constructing API subjects. This could lead to unintended subject mutations or potentially unauthorized API access if the NATS server relies on strict subject matching for authorization.
    * Step-by-step trigger:
        1. An attacker crafts a malicious stream or consumer name containing special characters (e.g., control characters, subject delimiters if any are missed in validation).
        2. The attacker uses the `nats.go` client to attempt to create a stream or consumer with this malicious name.
        3. If the server-side subject authorization relies on the stream or consumer name being part of the subject, the injected characters could bypass or alter the intended authorization scope.
        4. Although the provided code performs checks in `checkStreamName` and `checkConsumerName`, these checks are limited and might not cover all potentially harmful characters depending on the NATS server's subject parsing and authorization logic.
* Impact:
    * Potential for unauthorized access or manipulation of JetStream resources if server-side authorization is bypassed or altered due to subject injection.
    * Depending on the server-side implementation, this could lead to data breaches or unauthorized control over message streams.
* Vulnerability Rank: High
* Currently Implemented Mitigations:
    * The `checkStreamName` and `checkConsumerName` functions in `jsm.go` provide basic validation by disallowing whitespace and "." characters in stream and consumer names.
    * Source code location: `jsm.go:395`, `jsm.go:412`
* Missing Mitigations:
    * More comprehensive input sanitization for stream and consumer names, considering all characters that could be interpreted specially in NATS subjects or by the NATS server's authorization mechanisms.
    * Validation should ideally be performed against a strict whitelist of allowed characters rather than a blacklist of disallowed characters.
    * Documentation should explicitly warn against using special characters in stream and consumer names and recommend using only alphanumeric characters and underscores.
* Preconditions:
    * The attacker must have the ability to create JetStream streams or consumers, or influence the creation process if the application programmatically creates these resources based on external input.
    * The NATS server's authorization mechanism must rely on subject matching that includes stream or consumer names.
* Source Code Analysis:
    * The `checkStreamName` function in `jsm.go` at line 395 checks for empty stream names and the presence of "." and " " characters using `strings.ContainsAny`.
    * The `checkConsumerName` function in `jsm.go` at line 412 performs similar checks for consumer names, also using `strings.ContainsAny` to disallow "." and " " characters.
    * These validations are insufficient because they do not prevent other potentially harmful characters that could be used in subject injection attacks. Characters like `*`, `>`, control characters, or other subject delimiters (if any are missed) might bypass these checks and be processed in unintended ways by the NATS server or authorization logic.
    * The vulnerability lies in the limited scope of character validation, focusing only on whitespace and dots while neglecting other potentially dangerous characters in the context of NATS subjects and authorization.
* Security Test Case:
    1. **Setup:**
        * Start a NATS server instance with JetStream enabled and, if possible, configure a subject-based authorization system that relies on stream or consumer names in subjects.
        * Create a Go application that uses the `nats.go` client and JetStream management API.
    2. **Attempt Stream Creation with Malicious Name:**
        * In the Go application, attempt to create a JetStream stream with a name containing special characters, for example: `"stream*name"`.
        ```go
        package main

        import (
            "fmt"
            "log"

            "github.com/nats-io/nats.go"
            "github.com/nats-io/nats.go/jetstream"
        )

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

            streamName := "stream*name" // Malicious stream name
            streamCfg := jetstream.StreamConfig{
                Name:     streamName,
                Subjects: []string{"orders.>"},
            }
            _, err = js.CreateStream(ctx, streamCfg)
            if err != nil {
                fmt.Printf("Error creating stream: %v\n", err)
            } else {
                fmt.Printf("Stream '%s' created successfully\n", streamName)
            }
        }

        ```
    3. **Attempt Consumer Creation with Malicious Name:**
        * In the Go application, attempt to create a JetStream consumer with a name containing special characters, for example: `"consumer>name"`.
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

            consumerName := "consumer>name" // Malicious consumer name
            consumerCfg := jetstream.ConsumerConfig{
                Durable:   consumerName,
                AckPolicy: jetstream.AckExplicitPolicy,
            }
            _, err = js.CreateConsumer(ctx, "ORDERS", consumerCfg)
            if err != nil {
                fmt.Printf("Error creating consumer: %v\n", err)
            } else {
                fmt.Printf("Consumer '%s' created successfully\n", consumerName)
            }
        }
        ```
    4. **Verification:**
        * Run the Go applications and check if the stream or consumer creation succeeds with the malicious names.
        * Manually inspect the NATS server's state (e.g., using `nats stream info` or `nats consumer info` CLI commands) to confirm if the stream or consumer was created with the malicious name.
        * If subject-based authorization is configured on the server, attempt to exploit the created stream or consumer with the malicious name to bypass authorization rules. For instance, if authorization rules are based on exact stream names, the injected characters might alter the name in a way that bypasses these rules.

### Vulnerability 2: Potential Subject Confusion in Direct Get API due to Missing Subject Validation

* Vulnerability Name: Subject Confusion in Direct Get API
* Description:
    * The `GetLastMsg` function in `jsm.go` retrieves the last message for a given subject in a JetStream stream using the Direct Get API.
    * While the function checks for a valid stream name using `checkStreamName`, it does not perform any validation on the `subject` parameter itself.
    * If the `subject` parameter is not properly validated and sanitized, an attacker could inject special characters or wildcards into the subject.
    * This could potentially lead to the retrieval of messages from unintended subjects within the stream if the server's Direct Get API subject handling is not strictly exact-match based and is vulnerable to wildcard expansion or other subject manipulation.
    * Step-by-step trigger:
        1. An attacker crafts a malicious subject string containing wildcard characters (e.g., `ORDERS.*`, `ORDERS.>`).
        2. The attacker calls the `GetLastMsg` function with this malicious subject, intending to retrieve the last message for a seemingly legitimate subject but using the malicious subject to potentially broaden the scope.
        3. If the NATS server's Direct Get API subject matching is not strictly enforced as exact match and is susceptible to wildcard expansion or similar subject interpretation, messages from unintended subjects might be returned.
        4. This could lead to information disclosure if the attacker can retrieve messages they are not supposed to access based on the intended subject.
* Impact:
    * Potential for unauthorized access to messages from subjects that the attacker should not be able to access within a stream.
    * Information disclosure if messages from broader or different subjects than intended are retrieved.
* Vulnerability Rank: High
* Currently Implemented Mitigations:
    * The `checkStreamName` function is called to validate the stream name, but there is no validation for the `subject` parameter in `GetLastMsg`.
    * Source code location: `jsm.go:999`
* Missing Mitigations:
    * Input validation and sanitization for the `subject` parameter in the `GetLastMsg` function to prevent subject injection.
    * The validation should ensure that the subject is a valid NATS subject and does not contain any wildcard characters or other potentially harmful characters that could lead to unintended subject matching in the Direct Get API.
    * Documentation should recommend caution when using `GetLastMsg` with user-provided subjects and advise against using subjects with wildcards.
* Preconditions:
    * The attacker must have the ability to call the `GetLastMsg` function, or influence the parameters passed to it, with a malicious subject.
    * The NATS server's Direct Get API subject matching must not be strictly exact-match based and must be susceptible to wildcard expansion or other subject manipulation.
* Source Code Analysis:
    * The `GetLastMsg` function in `jsm.go` at line 999 calls the internal `getMsg` function, passing the `subject` parameter directly without any validation.
    * The `getMsg` function at line 1004 validates the `name` (stream name) using `checkStreamName`, but no similar validation is performed for the `subject` parameter.
    * This lack of validation for the `subject` in `GetLastMsg` is a potential vulnerability because it allows arbitrary subjects, including those with wildcards, to be passed to the Direct Get API, which might lead to unintended message retrieval if the server does not strictly enforce exact subject matching.
* Security Test Case:
    1. **Setup:**
        * Start a NATS server instance with JetStream enabled.
        * Create a JetStream stream named "TEST_STREAM" with subjects like `TEST_STREAM.SUBJECT1` and `TEST_STREAM.SUBJECT2`, and publish messages to both subjects.
        * Create a Go application that uses the `nats.go` client and JetStream API.
    2. **Attempt GetLastMsg with Malicious Subject:**
        * In the Go application, call `GetLastMsg` with a malicious subject like `TEST_STREAM.>` (wildcard subject) to attempt to retrieve messages from all subjects in the stream when only `TEST_STREAM.SUBJECT1` was intended.
        ```go
        package main

        import (
            "context"
            "fmt"
            "log"

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
        * Run the Go application and check if `GetLastMsg` with the malicious subject successfully retrieves messages.
        * Verify if the retrieved message's subject is from a broader scope than intended (e.g., if using `TEST_STREAM.>`, messages from both `TEST_STREAM.SUBJECT1` and `TEST_STREAM.SUBJECT2` are potentially retrieved instead of just from `TEST_STREAM.SUBJECT1`).
        * If successful, this indicates that subject injection is possible in the `GetLastMsg` API, potentially leading to unauthorized message access.

### Vulnerability 3: Potential WebSocket Frame Injection via Unvalidated Control Frame Payloads

* Vulnerability Name: WebSocket Frame Injection via Unvalidated Control Frame Payloads
* Description:
    * The `nats.go` library's WebSocket implementation in `ws.go` handles WebSocket control frames (Ping, Pong, Close).
    * The `handleControlFrame` function processes these frames, and for Close and Ping frames, it extracts the payload.
    * For Close frames, it further parses the payload for a status code and body. For Ping frames, it enqueues a Pong response with the same payload.
    * **Vulnerability:** The payload of control frames (especially Ping and Close) is not strictly validated for malicious content before being processed or echoed back in a Pong or used in a Close message. An attacker could inject crafted payloads within control frames that, when processed or reflected, might lead to unexpected behavior in the client or server, or potentially other connected WebSocket clients if the server echoes pings. While RFC6455 limits control frame payloads to 125 bytes and prohibits compression/fragmentation, complex payloads could still be crafted.
    * Step-by-step trigger:
        1. An attacker establishes a WebSocket connection to a NATS server via `nats.go` client.
        2. The attacker crafts a malicious payload (up to 125 bytes) designed to potentially exploit a vulnerability when processed or reflected. This payload could be designed to cause parsing issues on the receiving end, or if reflected, on another client. For example, the payload could be crafted to look like a valid WebSocket frame header if interpreted incorrectly downstream.
        3. The attacker sends a WebSocket Ping frame to the NATS server with the malicious payload.
        4. The `handleControlFrame` function in `nats.go` processes the Ping frame, extracts the payload, and enqueues a Pong frame with the *same* payload.
        5. The NATS server (or another component if server reflects pings to other clients) processes or reflects the crafted payload, potentially triggering unintended behavior due to lack of sanitization in `nats.go` and reliance on the server's or other clients' handling of arbitrary payloads in control frames. For instance, if the payload contains sequences that could be misinterpreted as frame headers by a weakly implemented websocket parser elsewhere in the system, it could lead to frame injection or confusion.
* Impact:
    * Potential for client-side or server-side misbehavior due to processing or reflection of maliciously crafted payloads in WebSocket control frames.
    * Although limited by control frame size, carefully crafted payloads could exploit vulnerabilities in WebSocket frame parsing or state management in NATS server or other clients if server echoes pings.
    * In case of Close frames, malicious payloads could lead to confusing close status codes or messages being displayed to users or logged by systems.
* Vulnerability Rank: High
* Currently Implemented Mitigations:
    * The `handleControlFrame` function in `ws.go` checks if the control frame payload size exceeds `wsMaxControlPayloadSize` (125 bytes).
    * Source code location: `ws.go:243`
* Missing Mitigations:
    * Input validation and sanitization of control frame payloads in `handleControlFrame` to prevent injection of malicious content.
    * For Ping frames, consider stripping or sanitizing the payload before echoing it back in a Pong response.
    * For Close frames, validate the status code and sanitize the body to ensure they conform to expected formats and do not contain potentially harmful characters or sequences.
    * Documentation should warn against echoing or logging control frame payloads without proper sanitization, especially if these payloads are derived from external input.
* Preconditions:
    * The attacker must be able to establish a WebSocket connection to the NATS server.
    * The NATS server or other connected WebSocket clients must be potentially vulnerable to processing or reflecting malicious payloads within WebSocket control frames.
* Source Code Analysis:
    * The `handleControlFrame` function in `ws.go` at line 238 is responsible for processing WebSocket control frames.
    * For `wsPingMessage` (line 277), it directly uses the received payload to enqueue a `wsPongMessage` using `r.nc.wsEnqueueControlMsg(r.nl, wsPongMessage, payload)`. No validation or sanitization is performed on `payload` before enqueuing.
    * For `wsCloseMessage` (line 241), it extracts the payload and parses it for a status code and body. While it checks for UTF-8 validity of the body, it does not perform deeper sanitization of the payload content itself before using parts of it (especially body) in error messages or close frame processing.
    * The vulnerability lies in the lack of validation of the *content* of control frame payloads. While size is checked, the actual data within the payload is processed and potentially reflected without sanitization, which could be exploited with carefully crafted payloads.
* Security Test Case:
    1. **Setup:**
        * Start a NATS server instance that supports WebSocket connections.
        * Create a Go application using `nats.go` client to establish a WebSocket connection.
        * Optionally, set up a monitoring tool or another WebSocket client to observe the traffic or server behavior.
    2. **Send Malicious Ping Frame:**
        * In the Go application, send a WebSocket Ping frame with a malicious payload. The payload could be crafted to be a sequence of bytes that, if misinterpreted, could resemble a WebSocket frame header or contain control characters that might cause issues on the receiving end. Example malicious payload: `[]byte{0x81, 0x05, 0x48, 0x65, 0x6c, 0x6c, 0x6f}` (This payload starts with what could be misinterpreted as a text frame header `0x81`).
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
        * Run the Go application to send the malicious Ping frame.
        * Monitor the NATS server logs and behavior for any anomalies, errors, or crashes.
        * If possible, observe the WebSocket traffic to see the Pong response from the server. Check if the malicious payload is echoed back verbatim in the Pong.
        * If another WebSocket client is connected and the server reflects pings, observe that client for any unexpected behavior or errors.
        * Analyze if the malicious payload caused any parsing errors, state corruption, or other unintended effects in the NATS server or client. A successful exploit might not cause immediate crashes but could lead to subtle misbehavior or vulnerabilities if the payload is designed to manipulate state or bypass certain checks when reflected or further processed.

**MISSING MITIGATIONS:**
* Comprehensive input sanitization for stream and consumer names in `checkStreamName` and `checkConsumerName` functions, considering all characters that could be interpreted specially in NATS subjects or by the NATS server's authorization mechanisms.
* Input validation and sanitization for the `subject` parameter in the `GetLastMsg` function to prevent subject injection.
* Input validation and sanitization of control frame payloads in `handleControlFrame` in `ws.go` to prevent WebSocket frame injection.
* Implement validation against a strict whitelist of allowed characters rather than a blacklist of disallowed characters for stream and consumer names and subjects in `GetLastMsg`.
* Update documentation to explicitly warn against using special characters in stream and consumer names and when using subjects in `GetLastMsg`, recommending only alphanumeric characters and underscores. Also, warn about potential risks of unvalidated control frame payloads in WebSocket connections.
* Consider implementing server-side validation and sanitization of stream and consumer names and subjects in Direct Get API as a defense-in-depth measure. And for control frame payloads if server reflects pings.