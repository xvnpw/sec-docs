## Vulnerability List

### Vulnerability 1: Path Traversal or Routing Bypass due to Composite Path Parameter Parsing

* Description:
    The `middleware/router.go` file contains a function `decodeCompositParams` that attempts to handle non-standard composite path parameters. This function recursively parses path segments after a standard path parameter (defined using curly braces `{}`). The parsing logic in `decodeCompositParams` is complex and potentially vulnerable to path traversal or routing bypass. By crafting a URL with specific composite path parameter patterns, an attacker might be able to manipulate the routing mechanism to access unintended endpoints or bypass security checks. This is because the custom parsing logic might not correctly sanitize or validate the path, potentially leading to interpretation issues in the routing decision.

    **Step-by-step trigger:**
    1. Identify an API endpoint that uses path parameters and is routed using `go-openapi/runtime/middleware/router`.
    2. Craft a URL that includes a standard path parameter followed by a composite parameter pattern that can be misinterpreted by the `decodeCompositParams` function. For example, if a path pattern is `/user/{username}/profile{/fragment}` and the code uses `decodeCompositParams` to parse `/fragment`, try to inject path traversal characters like `../` or manipulate the fragment part in a way that it alters the effective path used for routing after the composite parameter parsing.
    3. Send the crafted request to the application.
    4. Observe if the application routes the request to an unexpected handler or bypasses intended routing constraints, indicating a potential path traversal or routing bypass.

* Impact:
    - **High**: Successful exploitation could lead to unauthorized access to API endpoints, potentially bypassing security controls and exposing sensitive data or functionalities. In certain scenarios, it might even be possible to achieve path traversal if the parsed path is used to access file system resources, although this is less likely in this routing context. The primary impact is likely related to incorrect routing and authorization bypass.

* Vulnerability Rank: high

* Currently implemented mitigations:
    - None identified in the provided code. The code implements a custom parameter parsing logic, but does not include explicit sanitization or validation to prevent path traversal or routing bypass attacks in the `decodeCompositParams` function.

* Missing mitigations:
    - Input validation and sanitization within the `decodeCompositParams` function to prevent path traversal sequences (e.g., `../`, `..\\`) and other potentially malicious path manipulations.
    - More robust and standard path parameter parsing mechanism should be used instead of custom, potentially flawed logic. Consider using well-vetted path routing libraries that handle parameter parsing securely and consistently.

* Preconditions:
    - The application must be using `go-openapi/runtime/middleware/router` for routing requests.
    - API endpoints must be defined with path parameters followed by composite parameter patterns that trigger the vulnerable `decodeCompositParams` function.

* Source code analysis:
    - File: `/code/middleware/router.go`
    - Function: `decodeCompositParams(name string, value string, pattern string, names []string, values []string)`

    ```go
    func decodeCompositParams(name string, value string, pattern string, names []string, values []string) ([]string, []string) {
    	pleft := strings.Index(pattern, "{") // Find the index of '{' in the pattern
    	names = append(names, name)          // Append the current parameter name
    	if pleft < 0 {                       // If no '{' is found in the pattern (base case)
    		if strings.HasSuffix(value, pattern) { // Check if the value ends with the pattern
    			values = append(values, value[:len(value)-len(pattern)]) // If it does, append the part of the value before the suffix
    		} else {
    			values = append(values, "") // Otherwise, append an empty string
    		}
    	} else { // Recursive case if '{' is found in the pattern
    		toskip := pattern[:pleft]             // Part of the pattern before '{'
    		pright := strings.Index(pattern, "}")    // Find the index of '}' in the pattern
    		vright := strings.Index(value, toskip)  // Find the index of 'toskip' in the value
    		if vright >= 0 {                        // If 'toskip' is found in the value
    			values = append(values, value[:vright]) // Append the part of the value before 'toskip'
    		} else {
    			values = append(values, "") // Otherwise, append an empty string
    			value = ""                  // and set value to empty string
    		}
    		return decodeCompositParams(pattern[pleft+1:pright], value[vright+len(toskip):], pattern[pright+1:], names, values) // Recursive call
    	}
    	return names, values // Return the accumulated names and values
    }
    ```
    - Visualization:

    ```
    Path Pattern: /user/{username}/profile{/fragment}
    Incoming Path: /user/john/profile/settings

    1. decodeCompositParams("username", "john", "/profile{/fragment}", [], [])
       pleft = -1 (no '{' in "/profile{/fragment}")
       strings.HasSuffix("john", "/profile{/fragment}") is false
       values = [""]
       names = ["username"]
       return names, values  -> ["username"], [""] - Incorrect parsing

    Correct parsing should extract "john" as username and "/settings" as fragment if the path was intended to be /user/{username}/profile/{fragment}. However, the `decodeCompositParams` function is used to handle fragment/composing parameters *within* a path segment, which is non-standard and error-prone.

    The issue arises because this custom parsing logic attempts to handle path structures that are not standard URL path parameters, leading to potential misinterpretations of the path and routing decisions.

* Security test case:
    1. Deploy an application built using `go-openapi/runtime` that utilizes the `middleware/router` and has an endpoint with a path pattern similar to `/resource/{id}/action{/extra}`. Assume this endpoint should only be accessible to authenticated users with specific roles.
    2. Identify the base URL of the deployed application (e.g., `https://example.com`).
    3. Craft a malicious URL by injecting path traversal characters into the composite parameter part. For example, if the intended path is `/resource/123/action/view`, try a URL like `https://example.com/resource/123/action../unintended/admin/panel`. The part `../unintended/admin/panel` is injected into the composite parameter section `{/extra}`.
    4. Send an unauthenticated GET request to the crafted URL.
    5. Observe the application's response.
    6. **Expected behavior (without vulnerability):** The application should return a 404 Not Found or 401 Unauthorized error, as the crafted path should not match any valid route, or authentication/authorization should fail for the unintended path.
    7. **Vulnerable behavior (potential vulnerability):** If the application responds with a 200 OK or a different response indicating access to an unintended resource (e.g., admin panel content), it indicates a routing bypass vulnerability. The `decodeCompositParams` function might have incorrectly parsed the path, leading the router to match the request to a different, potentially sensitive endpoint.