### Vulnerability List

- Vulnerability Name: Insecure Direct Object Reference (IDOR) on Proxy Node Configurations
- Description:
    1. An attacker obtains a valid API key.
    2. The attacker sends a GET request to `/api/proxy_configs/{node_id}/` endpoint, replacing `{node_id}` with the ID of a proxy node.
    3. The server authenticates the request using the API key.
    4. The server retrieves the proxy node configuration based on the provided `node_id`.
    5. The server returns the proxy node configurations in JSON format without verifying if the API key is authorized to access the configuration of this specific node.
    6. The attacker can iterate through different `node_id` values to retrieve configurations for various proxy nodes.
- Impact:
    - Exposure of sensitive proxy node configuration details such as server addresses, ports, encryption methods, and passwords if included in configurations.
    - Attackers can use this information to directly target proxy servers, potentially bypassing application-level security controls, launching denial-of-service attacks against proxy nodes, or attempting to intercept user traffic.
- Vulnerability Rank: High
- Currently implemented mitigations:
    - API key authentication is implemented using the `@api_authorized` decorator in `apps/api/views.py`, which verifies the presence and validity of an API key in the request. This is a basic authentication measure.
- Missing mitigations:
    - Missing authorization checks to verify if the authenticated API key has the necessary permissions to access the configuration of the requested proxy node (`node_id`).
    - Role-based access control (RBAC) or Access Control Lists (ACLs) are not implemented to manage API key permissions and restrict access to specific resources.
- Preconditions:
    - A publicly accessible instance of the django-sspanel application must be deployed.
    - An attacker must possess a valid API key. This could be obtained through legitimate means (if API keys are intended for general use without authorization controls), or through compromising an administrative account or exploiting another vulnerability to retrieve an API key.
- Source code analysis:
    ```python
    # File: /code/apps/api/views.py
    from django.views import View
    from django.http import JsonResponse, HttpResponseBadRequest
    from django.utils.decorators import method_decorator

    from apps.utils import api_authorized
    from apps.proxy import models as m

    class ProxyConfigsView(View):
        @method_decorator(api_authorized)
        def get(self, request, node_id):
            node = m.ProxyNode.get_or_none(node_id) # [POINT OF VULNERABILITY] - Retrieves node by ID without authorization check
            return (
                JsonResponse(node.get_proxy_configs()) if node else HttpResponseBadRequest()
            )
    ```
    The `ProxyConfigsView` in `/code/apps/api/views.py` is protected by the `@api_authorized` decorator, which provides authentication by checking the API key. However, after successful authentication, the code directly retrieves the `ProxyNode` based on the `node_id` path parameter using `m.ProxyNode.get_or_none(node_id)` without any further authorization checks. This means any valid API key, regardless of its intended scope or permissions, can be used to access the configurations of any `ProxyNode` by simply altering the `node_id` in the request. There is no mechanism to ensure that the API key is authorized to access the configuration of the specific `ProxyNode` being requested.

- Security test case:
    1. **Setup:** Deploy a publicly accessible instance of django-sspanel with at least two proxy nodes, for example, Node A (ID: 1) and Node B (ID: 2). Obtain a valid API key. Assume for this test that any valid API key grants access after authentication, which reflects the lack of authorization in the code.
    2. **Step 1: Request Configuration for Node A:** As an attacker, send a GET request to the endpoint for retrieving proxy configurations for Node A. Use the obtained API key in the `token` parameter and set `node_id` to 1.
        ```
        GET /api/proxy_configs/1/?token=<YOUR_API_KEY> HTTP/1.1
        Host: <YOUR_DJANGO_SSPANEL_INSTANCE>
        ```
    3. **Step 2: Observe Response for Node A:** Examine the response from the server. It should return a JSON response containing the proxy configurations for Node A, indicating successful access.
    4. **Step 3: Request Configuration for Node B:** Now, send a similar GET request, but this time, change the `node_id` to 2 to target Node B, while using the same API key.
        ```
        GET /api/proxy_configs/2/?token=<YOUR_API_KEY> HTTP/1.1
        Host: <YOUR_DJANGO_SSPANEL_INSTANCE>
        ```
    5. **Step 4: Observe Response for Node B:** Examine the response for this second request. It should also return a JSON response containing the proxy configurations for Node B, even though there was no specific authorization granted for this API key to access Node B's configuration.
    6. **Step 5: Verify Vulnerability:** If both requests are successful and return the configurations for different proxy nodes using the same API key, it confirms the Insecure Direct Object Reference vulnerability. This demonstrates that the API key, once authenticated, can access configurations of arbitrary proxy nodes without proper authorization checks.