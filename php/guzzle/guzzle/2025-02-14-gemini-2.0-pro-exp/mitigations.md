# Mitigation Strategies Analysis for guzzle/guzzle

## Mitigation Strategy: [Strict Allowlist for External Requests (within Guzzle)](./mitigation_strategies/strict_allowlist_for_external_requests__within_guzzle_.md)

*   **Description:**
    1.  **Identify all code locations** where Guzzle is used to make external requests (look for `GuzzleHttp\Client` and methods like `get()`, `post()`, `request()`).
    2.  **Create a centralized configuration file** (e.g., `config/allowed_domains.php`) or use environment variables for the allowlist.
    3.  **Modify Guzzle request code:** *Before* making a Guzzle request, check if the target URL's host (or IP) is in the allowlist. If not, throw an exception.  This logic should be *directly integrated* with the Guzzle request process.
        ```php
        use GuzzleHttp\Client;
        use GuzzleHttp\Exception\RequestException;

        function makeExternalRequest(string $userInput): string
        {
            $allowedDomains = require 'config/allowed_domains.php';
            $baseUrl = 'https://api.example.com'; // Example

            $url = $baseUrl . '/' . $userInput; // User input for path ONLY
            $parsedUrl = parse_url($url);

            if (!in_array($parsedUrl['host'], $allowedDomains)) {
                throw new \Exception("Invalid target domain: " . $parsedUrl['host']);
            }

            $client = new Client(); // Guzzle client instantiation
            try {
                $response = $client->request('GET', $url); // Guzzle request
                return $response->getBody()->getContents();
            } catch (RequestException $e) {
                throw $e;
            }
        }
        ```

*   **Threats Mitigated:**
    *   **Server-Side Request Forgery (SSRF):** (Severity: High) - Prevents Guzzle from requesting arbitrary resources.
    *   **Open Redirect (indirectly):** (Severity: Medium) - Helps control the initial request target.

*   **Impact:**
    *   **SSRF:** Risk reduction: Very High.
    *   **Open Redirect:** Risk reduction: Moderate.

*   **Currently Implemented:** Partially. `ApiController` has an allowlist for one endpoint, but it's not consistently applied to all Guzzle requests.

*   **Missing Implementation:**
    *   `UserController` (avatar fetching) and `ReportController` (external data fetching) lack allowlist checks within their Guzzle request logic.
    *   Centralized allowlist configuration is missing.

## Mitigation Strategy: [Strict Redirect Handling (using Guzzle's options)](./mitigation_strategies/strict_redirect_handling__using_guzzle's_options_.md)

*   **Description:**
    1.  **Locate all Guzzle client configurations.**
    2.  **Configure `allow_redirects`:** Use Guzzle's `'allow_redirects'` option *extensively*.  Set it to `false` to disable redirects, or (preferably) use an array for fine-grained control:
        ```php
        $client = new Client([
            'allow_redirects' => [
                'max'             => 5,     // Limit redirects
                'strict'          => true,  // RFC compliant redirects
                'referer'         => true,  // Add Referer header
                'protocols'       => ['https'], // Only HTTPS
                'on_redirect'     => function (
                    RequestInterface $request,
                    ResponseInterface $response,
                    UriInterface $uri
                ) {
                    // Guzzle-specific redirect validation
                    $allowedDomains = require 'config/allowed_domains.php';
                    if (!in_array($uri->getHost(), $allowedDomains)) {
                        throw new \Exception("Invalid redirect: " . $uri->getHost());
                    }
                },
            ],
            // ... other Guzzle options
        ]);
        ```
    3.  **Implement `on_redirect` callback:** This is *critical*.  This Guzzle callback allows you to inspect the redirect target *before* Guzzle follows it.  Use the allowlist within this callback.

*   **Threats Mitigated:**
    *   **Open Redirect:** (Severity: Medium)
    *   **SSRF (via redirects):** (Severity: High)

*   **Impact:**
    *   **Open Redirect:** Risk reduction: High.
    *   **SSRF (via redirects):** Risk reduction: High.

*   **Currently Implemented:** No. Guzzle is using default redirect behavior (no validation).

*   **Missing Implementation:** This is missing entirely. All Guzzle clients need the `'allow_redirects'` option and the `on_redirect` callback.

## Mitigation Strategy: [Redact Sensitive Information using Guzzle Middleware](./mitigation_strategies/redact_sensitive_information_using_guzzle_middleware.md)

*   **Description:**
    1.  **Create Guzzle middleware:**  Write custom middleware to intercept requests and responses *within Guzzle*.
        ```php
        use GuzzleHttp\Middleware;
        use Psr\Http\Message\RequestInterface;
        use Psr\Http\Message\ResponseInterface;

        $redactMiddleware = Middleware::mapRequest(function (RequestInterface $request) {
            $request = $request->withoutHeader('Authorization'); // Redact
            // ... redact other sensitive data from request body
            return $request;
        });

        $redactMiddlewareResponse = Middleware::mapResponse(function (ResponseInterface $response) {
            //Redact sensitive data from response
            return $response;
        });

        $stack = HandlerStack::create();
        $stack->push($redactMiddleware);
        $stack->push($redactMiddlewareResponse);

        $client = new Client([
            'handler' => $stack, // Apply the middleware
            // ... other Guzzle options
        ]);
        ```
    2.  **Apply the middleware:** Add the middleware to the Guzzle handler stack using the `'handler'` option when creating the client.
    3.  **Redact sensitive data:** Within the middleware, remove or replace sensitive information (e.g., `Authorization` headers, parts of the request/response body) *before* it's passed to the next handler (which might include logging).

*   **Threats Mitigated:**
    *   **Sensitive Data Exposure in Logs:** (Severity: Medium to High) - Prevents Guzzle from logging sensitive data.

*   **Impact:**
    *   **Sensitive Data Exposure:** Risk reduction: High.

*   **Currently Implemented:** No.  No custom Guzzle middleware is used for redaction.

*   **Missing Implementation:**  This needs to be implemented and applied to *all* Guzzle client instances.

## Mitigation Strategy: [Proper Cookie Handling (using Guzzle's `CookieJar`)](./mitigation_strategies/proper_cookie_handling__using_guzzle's__cookiejar__.md)

*   **Description:**
    1.  **Identify Cookie Usage:** Check for `'cookies' => true` or `GuzzleHttp\Cookie\CookieJar` in Guzzle configurations.
    2.  **Disable Cookies (if possible):** If cookies are *not* needed, set `'cookies' => false` in the Guzzle client:
        ```php
        $client = new Client(['cookies' => false]);
        ```
    3.  **Use Dedicated `CookieJar` (if necessary):** If cookies *are* required, create a *separate* `CookieJar` instance for each service or context.  Do *not* use the global default.
        ```php
        use GuzzleHttp\Cookie\CookieJar;

        $cookieJar = new CookieJar();
        $client = new Client(['cookies' => $cookieJar]);
        ```
    4.  **Clear `CookieJar`:**  Explicitly clear the `CookieJar` when a session ends or a user logs out, using Guzzle's `CookieJar` methods:
        ```php
        $cookieJar->clear(); // Clear all
        $cookieJar->clear('example.com', '/path', 'cookie_name'); // Clear specific
        ```

*   **Threats Mitigated:**
    *   **Session Fixation:** (Severity: Medium)
    *   **Cookie-Based Attacks:** (Severity: Variable)

*   **Impact:**
    *   **Session Fixation/Cookie Attacks:** Risk reduction: Moderate to High.

*   **Currently Implemented:** No. Default Guzzle cookie handling is used without specific management.

*   **Missing Implementation:**
    *   Review of all Guzzle configurations for cookie usage.
    *   Implementation of dedicated `CookieJar` instances or disabling cookies.
    *   Code to clear cookie jars.

## Mitigation Strategy: [Enforce TLS/SSL Certificate Verification (using Guzzle's `verify` option)](./mitigation_strategies/enforce_tlsssl_certificate_verification__using_guzzle's__verify__option_.md)

*   **Description:**
    1.  **Locate all Guzzle client configurations.**
    2.  **Verify `verify` option:** Ensure that the `verify` option is either *not* set (defaults to `true`) or is explicitly set to `true`:
        ```php
        $client = new Client(['verify' => true]); // Correct
        // OR
        $client = new Client(); // Also correct (defaults to true)
        ```
        *Never* set `'verify' => false` in production.
    3.  **CA Bundle (if needed):** If using a custom CA bundle, ensure `verify` points to the correct path, and keep the bundle updated:
        ```php
        $client = new Client(['verify' => '/path/to/cacert.pem']);
        ```

*   **Threats Mitigated:**
    *   **Man-in-the-Middle (MITM) Attacks:** (Severity: High)

*   **Impact:**
    *   **MITM Attacks:** Risk reduction: Very High.

*   **Currently Implemented:** Mostly. Most clients use the default (`true`), but a legacy testing script has `'verify' => false`.

*   **Missing Implementation:**
    *   The testing script needs to be corrected to use valid certificates or remove the incorrect setting.

