- Vulnerability Name: Medium-rank CPU exhaustion via crafted Accept header with excessive q-value digits
  - Description:
    1. The `ParseAccept` function in `header/header.go` parses HTTP Accept headers.
    2. The `expectQuality` function is responsible for parsing the quality value (q-value) in the Accept header.
    3. `expectQuality` contains a loop that iterates through digits after the decimal point of the q-value.
    4. An attacker can send a crafted HTTP request with an `Accept-*` header containing a very long sequence of digits after the decimal point in a q-value (e.g., `Accept-Encoding: gzip;q=0.<long_digit_sequence>`).
    5. Processing such a header will cause the `expectQuality` function to iterate for an extended period, consuming CPU resources.
    6. If multiple such requests are sent concurrently, it can lead to noticeable CPU exhaustion on the server, potentially impacting the performance and availability of the service.
  - Impact: CPU exhaustion can degrade service performance and availability. While not a full denial of service in the sense of crashing the application, it can significantly impact responsiveness.
  - Vulnerability Rank: high
  - Currently implemented mitigations: None in the provided code.
  - Missing mitigations:
    - Input validation/Limiting digits: Implement a limit on the number of digits processed after the decimal point in the `expectQuality` function. A reasonable limit (e.g., 3 digits as per HTTP spec examples) should be enforced.
    - Timeout for header parsing: Consider implementing a timeout mechanism for the entire header parsing process, although limiting digits in `expectQuality` is a more targeted and effective mitigation for this specific vulnerability.
  - Preconditions:
    - The Prometheus client library is used in a server application that processes HTTP requests.
    - The application uses the `httputil.NegotiateContentEncoding` or similar functions that rely on `header.ParseAccept` to process Accept headers from external requests.
    - The application is publicly accessible.
  - Source code analysis:
    ```go
    func expectQuality(s string) (q float64, rest string) {
    	...
    	s = s[1:]
    	i := 0
    	n := 0
    	d := 1
    	for ; i < len(s); i++ { // Vulnerable loop
    		b := s[i]
    		if b < '0' || b > '9' {
    			break
    		}
    		n = n*10 + int(b) - '0'
    		d *= 10
    	}
    	return q + float64(n)/float64(d), s[i:]
    }
    ```
    The `for` loop within `expectQuality` function is the area of concern. It iterates as long as digits are encountered. A malicious actor can provide a very long string of digits, causing this loop to consume excessive CPU cycles.
  - Security test case:
    1. Setup: Deploy an application that uses `github.com/prometheus/client_golang` and is configured to use `httputil.NegotiateContentEncoding` or similar functionality that parses Accept headers. Ensure the application is publicly accessible or accessible within a test environment where you can monitor CPU usage.
    2. Tool: Use `curl` or a similar HTTP client.
    3. Crafted Request: Send an HTTP request to the application with a crafted `Accept-Encoding` header. The header should contain a long sequence of digits in the q-value. Example `curl` command:
       ```bash
       curl -H "Accept-Encoding: gzip;q=0.1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890" http://<target-application-url>/<endpoint>
       ```
       Replace `<target-application-url>/<endpoint>` with the actual URL of the target application endpoint. You can increase the digit sequence length further for more pronounced effect.
    4. Monitoring: Monitor the CPU usage of the server running the application while sending the crafted request.
    5. Verification: Observe if there is a noticeable increase in CPU usage when processing the request with the long q-value digits compared to normal requests without such headers. Repeat sending multiple concurrent requests with the crafted header to amplify the CPU usage and observe potential performance degradation.