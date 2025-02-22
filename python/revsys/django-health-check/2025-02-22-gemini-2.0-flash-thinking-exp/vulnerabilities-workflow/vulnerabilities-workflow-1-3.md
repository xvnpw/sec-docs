- Vulnerability name: HTTP Accept Header Parsing Vulnerability (ReDoS)
- Description:
    - Step 1: An attacker sends an HTTP GET request to the health check endpoint (e.g., `/ht/`).
    - Step 2: The attacker crafts a malicious `Accept` header with a long string containing repeated and complex patterns designed to exploit regex backtracking. Example malicious header: `Accept: text/html,text/html,text/html,...` or `Accept: text/html;q=0.1,text/html;q=0.1,text/html;q=0.1,...` or even more complex patterns using media type parameters.
    - Step 3: The Django application, using `django-health-check`, receives the request and the `MainView.get` method is invoked.
    - Step 4: Inside `MainView.get`, the `MediaType.parse_header` function is called to parse the `Accept` header using a regular expression.
    - Step 5: The crafted malicious `Accept` header causes the regular expression engine to perform excessive backtracking due to the regex pattern's structure and the input's complexity.
    - Step 6: This backtracking consumes a significant amount of CPU resources on the server.
    - Step 7: The server's performance degrades, potentially leading to slow response times for all users or even service unavailability.
- Impact: High. Successful exploitation can lead to excessive CPU consumption, resulting in degraded performance and potential service disruption for legitimate users.
- Vulnerability rank: High
- Currently implemented mitigations: None. The project does not currently implement any specific mitigations against ReDoS attacks in the `Accept` header parsing logic.
- Missing mitigations:
    - Implement a more efficient and secure method for parsing the `Accept` header, potentially avoiding complex regular expressions or using ReDoS-resistant regex patterns.
    - Introduce a limit on the length or complexity of the `Accept` header that the application will process to prevent excessively long or complex inputs from triggering ReDoS.
    - Implement request timeouts to limit the processing time for individual requests, mitigating the impact of ReDoS by preventing a single request from monopolizing server resources for too long.
    - Consider using a dedicated, well-vetted library for HTTP header parsing which is designed to be robust against such attacks.
- Preconditions:
    - The `django-health-check` application is installed and enabled in a Django project.
    - The health check endpoint (e.g., `/ht/`) is publicly accessible without any rate limiting or WAF rules in place to block malicious requests.
    - The server has limited CPU resources or is under load, making it susceptible to resource exhaustion from CPU-intensive operations.
- Source code analysis:
    - The vulnerability is located in `health_check/views.py` within the `MediaType` class, specifically in the `pattern` attribute and the `parse_header` method.
    - The `pattern` is a compiled regular expression designed to parse the components of an HTTP `Accept` header.
    - The regex pattern `r"""..."""` uses quantifiers like `*` which, combined with nested groups and alternations, can lead to catastrophic backtracking when processing maliciously crafted input strings.
    - The `parse_header` method splits the `Accept` header string by commas and then uses `MediaType.from_string` to parse each media type component using the vulnerable regex.
    - A crafted `Accept` header with repeated or nested patterns can cause the regex engine to explore a large number of backtracking paths, leading to increased CPU usage and processing time.
    ```python
    class MediaType:
        pattern = re.compile(
            r"""
              ^
              (?P<mime_type>
                (\w+|\*)                      # Media type, or wildcard
                /
                ([\w\d\-+.]+|\*)              # subtype, or wildcard
              )
              (
                \s*;\s*                       # parameter separator with optional whitespace
                q=                            # q is expected to be the first parameter, by RFC2616
                (?P<weight>
                  1([.]0{1,3})?               # 1 with up to three digits of precision
                  |
                  0([.]\d{1,3})?              # 0.000 to 0.999 with optional precision
                )
              )?
              (
                \s*;\s*                       # parameter separator with optional whitespace
                [-!#$%&'*+.^_`|~0-9a-zA-Z]+   # any token from legal characters
                =
                [-!#$%&'*+.^_`|~0-9a-zA-Z]+   # any value from legal characters
              )*
              $
            """,
            re.VERBOSE,
        )

        @classmethod
        def parse_header(cls, value="*/*"):
            """Parse HTTP accept header and return instances sorted by weight."""
            yield from sorted(
                (
                    cls.from_string(token.strip())
                    for token in value.split(",")
                    if token.strip()
                ),
                reverse=True,
            )
    ```
- Security test case:
    - Step 1: Deploy the `django-health-check` application to a test server and ensure the health check endpoint is accessible.
    - Step 2: Monitor the CPU usage of the server using tools like `top`, `htop`, or cloud provider monitoring dashboards to establish a baseline CPU usage when the health check endpoint is accessed normally.
    - Step 3: Use a tool like `curl`, `Postman`, or a custom script to send an HTTP GET request to the health check endpoint (`/ht/`) with a crafted, malicious `Accept` header. A sample malicious header could be:
      ```
      Accept: text/html,text/html,text/html,text/html,text/html,text/html,text/html,text/html,text/html,text/html,text/html,text/html,text/html,text/html,text/html,text/html,text/html,text/html,text/html,text/html,text/html,text/html,text/html,text/html,text/html,text/html,text/html,text/html,text/html,text/html,text/html,text/html,text/html,text/html,text/html,text/html,text/html,text/html,text/html,text/html,text/html,text/html,text/html,text/html,text/html,text/html,text/html,text/html,text/html,text/html,text/html,text/html,text/html,text/html,text/html,text/html,text/html,text/html,text/html,text/html,text/html,text/html,text/html,text/html,text/html,text/html,text/html,text/html,text/html,text/html,text/html,text/html,text/html,text/html,text/html,text/html,text/html,text/html,text/html,text/html,text/html,text/html,text/html,text/html,text/html,text/html,text/html,text/html,text/html,text/html,text/html,text/html,text/html,text/html,text/html,text/html,text/html,text/html,text/html,text/html
      ```
    - Step 4: While sending the malicious request, monitor the server's CPU usage.
    - Step 5: Observe if there is a significant increase in CPU usage compared to the baseline established in Step 2. If the CPU usage spikes and remains high during and after the request, and the response time is significantly delayed or the server becomes unresponsive, it confirms the ReDoS vulnerability.