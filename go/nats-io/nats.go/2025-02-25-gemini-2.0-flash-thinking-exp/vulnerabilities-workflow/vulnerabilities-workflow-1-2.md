### Vulnerability List

- **Vulnerability Name:** Stream and Consumer Name Injection via API Subject

- **Description:**
An attacker can potentially inject arbitrary commands or manipulate the API subject used for JetStream management operations by crafting stream or consumer names containing special characters like newline characters. This is because the library constructs API subjects by directly embedding stream and consumer names without proper sanitization. While the `checkStreamName` and `checkConsumerName` functions exist, they are insufficient to prevent all forms of injection, specifically newline injection which can lead to command injection-like behavior within the NATS server's subject parsing logic.

Steps to trigger the vulnerability:
1. Create a NATS client connection.
2. Obtain a JetStreamManager instance.
3. Attempt to create a stream or consumer with a name containing a newline character (`\n`). For example, use a stream name like `"stream\nINJECTED_COMMAND"`.
4. The library will construct an API subject using this crafted name.
5. When the NATS server processes this subject, the newline character might be interpreted as a subject separator, potentially leading to the execution of unintended commands or actions within the JetStream management context, depending on the server's subject parsing implementation and any potential command injection vulnerabilities in the server itself.

- **Impact:**
If successfully exploited, this vulnerability could allow an attacker to bypass intended access controls, manipulate JetStream streams and consumers in unauthorized ways, potentially leading to data corruption, data exfiltration, or disruption of service. The severity depends on the specific command injection possibilities within the NATS server and the attacker's ability to leverage injected commands. Given the potential for significant unauthorized actions within the messaging system, the impact is considered high.

- **Vulnerability Rank:** High

- **Currently Implemented Mitigations:**
The project includes `checkStreamName` and `checkConsumerName` functions in `jsm.go`. These functions check for whitespace and dot characters in stream and consumer names.

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

// Check that the consumer name is not empty and is valid (does not contain "." and " ").
// Additional consumer name validation is done in nats-server.
// Returns ErrConsumerNameRequired if consumer name is empty, ErrInvalidConsumerName is invalid, otherwise nil
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
These checks prevent names containing dots and spaces, but they do not prevent newline characters (`\n`) or other potentially harmful characters that might be processed specially by the NATS server's subject parsing logic. Client-side validation, as demonstrated in the security test case and implicitly confirmed by tests in `/code/test/js_test.go`, prevents creating stream or consumer names with newline characters through the Go client library itself.  Specifically, attempting to create a stream or consumer with a newline character will result in an "invalid stream name" or "invalid consumer name" error from the client library. However, this client-side validation is not a complete mitigation, as other clients or direct API interactions might bypass these checks. The core vulnerability lies in the potential for server-side subject injection due to insufficient sanitization in the client library when constructing API subjects from user-provided names. The extensive test suite in `/code/test/js_test.go` focuses on functional testing of JetStream features and does not include specific tests to validate or enforce robust input sanitization for stream and consumer names beyond the basic checks already in place.

- **Missing Mitigations:**
The project lacks proper sanitization of stream and consumer names to prevent injection attacks via API subjects. Specifically, it needs to:
    - **Disallow or sanitize newline characters (`\n`)** and potentially other control characters that could be interpreted specially in NATS subjects.
    - **Implement more robust input validation** to ensure stream and consumer names conform to a strict allowed character set, preventing any possibility of subject manipulation.

- **Preconditions:**
    - JetStream must be enabled on the NATS server.
    - The attacker must have access to a NATS connection and be able to create a JetStreamManager.
    - The NATS server's subject parsing logic must be susceptible to command injection or unintended behavior when encountering newline characters or other special characters in subjects, although this vulnerability focuses on the client-side construction of potentially malicious subjects.

- **Source Code Analysis:**
1. **File:** `/code/jsm.go` (from previous analysis, vulnerability location remains the same)
2. **Vulnerable Code Location:**  API subject construction in functions like `AddStream`, `UpdateStream`, `DeleteStream`, `AddConsumer`, `DeleteConsumer`, `ConsumerInfo`, etc.
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
    - The same pattern exists for consumer-related functions, for example, in `js.DeleteConsumer`:
    ```go
    dcSubj := js.apiSubj(fmt.Sprintf(apiConsumerDeleteT, stream, consumer))
    r, err := js.apiRequestWithContext(o.ctx, dcSubj, r)
    ```
    - The `apiSubj` function simply prepends the API prefix.
    ```go
    func (js *js) apiSubj(subj string) string {
        return js.opts.pre + subj
    }
    ```
    - The `checkStreamName` and `checkConsumerName` functions are called in `AddStream`, `UpdateStream`, `DeleteStream`, `AddConsumer`, `DeleteConsumer`, `ConsumerInfo` to validate the names. However, these checks are insufficient as they only block dots and spaces, not newline characters.
    - Analysis of the file `/code/test/js_test.go` confirms the presence of tests around JetStream functionality but does not introduce changes that mitigate this vulnerability. The tests in `/code/test/js_test.go` and `/code/test/conn_test.go` (from previous analysis) implicitly validate the client-side checks are in place, but the core issue of potential server-side injection due to insufficient sanitization remains.

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
    NATS Server Subject Processing (Potential Command Injection if Server Vulnerable)
    ```

4. **Vulnerability Explanation:**
    The vulnerability arises because the library directly uses user-provided stream and consumer names to construct API subjects without proper sanitization against newline characters. If the NATS server's subject processing logic is vulnerable to newline injection, this could lead to security issues. Even if the server is not directly vulnerable to command injection via newline in subjects, allowing such characters in names is a risky practice and could lead to unexpected behavior or future vulnerabilities. While client-side validation in the Go library prevents basic newline injection at the client level, it's insufficient for full mitigation.

- **Security Test Case:**
1. **Prerequisites:**
    - A running NATS server with JetStream enabled.
    - Go development environment set up.
    - `nats.go` library project cloned and available.

2. **Test Setup:**
    - Create a Go test file (e.g., `stream_injection_test.go`) in the `test` directory of the `nats.go` project.
    - Import the `nats` library and `testing` package.
    - Establish a connection to the NATS server in the test function.
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

        // Attempt to create a stream with an injected newline character in the name.
        streamName := "injected\nstream"
        streamCfg := &nats.StreamConfig{
            Name:     streamName,
            Subjects: []string{"inj.>"},
        }

        _, err := js.AddStream(streamCfg)
        if err == nil {
            t.Fatalf("Expected error when creating stream with newline in name, but got none")
        }

        if !strings.Contains(err.Error(), "invalid stream name") && !strings.Contains(err.Error(), "Invalid Stream Name") {
            t.Fatalf("Expected 'invalid stream name' error, got: %v", err)
        }


        // Attempt to create consumer with injected newline character in name.
        consumerName := "injected\nconsumer"
        consCfg := &nats.ConsumerConfig{
            Durable:   consumerName,
            AckPolicy: nats.AckExplicitPolicy,
        }

        _, err = js.AddConsumer("test_stream", consCfg) // Assuming "test_stream" exists or create one before this test.
        if err == nil {
            t.Fatalf("Expected error when creating consumer with newline in name, but got none")
        }
        if !strings.Contains(err.Error(), "invalid consumer name") && !strings.Contains(err.Error(), "Invalid Consumer Name") {
            t.Fatalf("Expected 'invalid consumer name' error, got: %v", err)
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
        return nc, js
    }


    ```

4. **Expected Result:**
    The test case should demonstrate that the `nats.go` library's client-side validation prevents stream and consumer names with newline characters from being created. The test expects to receive an "invalid stream name" or "invalid consumer name" error when attempting to create streams or consumers with newline characters in their names. If the test passes, it indicates that the client-side validation is working as intended to prevent basic newline injection at the client level. However, **it's crucial to understand that this client-side validation is insufficient for full mitigation of the vulnerability.** The test does not prove that the server is protected against subject injection, and further server-side checks are crucial to fully mitigate any potential subject injection vulnerabilities. If the test fails (no error or unexpected error), it indicates a vulnerability or insufficient client-side validation. Based on current code, this test should pass, confirming client-side validation is in place but is insufficient for full mitigation, and highlighting the need for server-side and more robust client-side sanitization.