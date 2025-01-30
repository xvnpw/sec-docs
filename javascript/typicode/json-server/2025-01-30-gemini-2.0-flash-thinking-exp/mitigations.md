# Mitigation Strategies Analysis for typicode/json-server

## Mitigation Strategy: [Restrict Usage to Development and Testing Environments](./mitigation_strategies/restrict_usage_to_development_and_testing_environments.md)

**Description:**
1.  **Define Intended Use:** Clearly establish that `json-server` is solely for local development and testing. It should **never** be deployed to staging or production environments.
2.  **Local Installation:** Install `json-server` as a development dependency (`devDependencies` in `package.json`). This ensures it's not included in production builds.
3.  **Development Scripts Only:**  Use `json-server` only in development-specific scripts (e.g., `npm run dev`, `yarn start:dev`). Ensure these scripts are not used in production deployment processes.
4.  **Environment Checks (Optional):**  Within your application's code or build scripts, add checks to explicitly prevent starting or using `json-server` if the environment is detected as staging or production.
**Threats Mitigated:**
*   **Unauthorized Access (High Severity):**  `json-server` lacks built-in security. Production deployment exposes data without authentication.
*   **Data Modification/Deletion (High Severity):**  Unprotected production `json-server` allows anyone to modify or delete data.
*   **Data Exposure (Medium Severity):**  Exposing data through an unsecured `json-server` is a data breach risk.
*   **Denial of Service (Low to Medium Severity):** Publicly accessible `json-server` is vulnerable to simple DoS attacks.
**Impact:**
*   **Unauthorized Access:** High Risk Reduction - Eliminates risk in production by preventing deployment.
*   **Data Modification/Deletion:** High Risk Reduction - Eliminates risk in production by preventing deployment.
*   **Data Exposure:** High Risk Reduction - Prevents public exposure in production.
*   **Denial of Service:** Medium Risk Reduction - Prevents public exposure, reducing DoS risk from public internet.
**Currently Implemented:**
*   **Local Installation:** Likely implemented - `json-server` is probably a `devDependency`.
**Missing Implementation:**
*   **Environment Checks:** Potentially missing - Explicit environment checks to prevent accidental production usage might not be in place.
*   **Strict Policy Enforcement:**  Policy might exist, but consistent enforcement across development teams might be lacking.

## Mitigation Strategy: [Limit Functionality - Restrict Write Operations (Simulated Read-Only)](./mitigation_strategies/limit_functionality_-_restrict_write_operations__simulated_read-only_.md)

**Description:**
1.  **Custom Middleware (json-server):** Create custom middleware function in `json-server` (using `--middlewares` flag or programmatic API).
2.  **Intercept Write Methods:** Within the middleware, intercept requests with HTTP methods `POST`, `PUT`, `PATCH`, and `DELETE`.
3.  **Reject Write Requests:**  For intercepted write requests, return a 403 Forbidden or 405 Method Not Allowed response.
4.  **Allow Read Requests:** Allow `GET` and `HEAD` requests to pass through normally to `json-server`'s default handlers.
5.  **Alternative - Application-Side Restriction:** If your application is the only client interacting with `json-server`, implement the restriction on the application side by simply not sending `POST`, `PUT`, `PATCH`, or `DELETE` requests.
**Threats Mitigated:**
*   **Data Modification/Deletion (High Severity):** Prevents accidental or unintended data modification or deletion through `json-server`'s API.
**Impact:**
*   **Data Modification/Deletion:** High Risk Reduction - Eliminates the risk of data modification/deletion via `json-server` endpoints.
**Currently Implemented:**
*   **Potentially Missing:**  Read-only mode is likely not implemented as it requires custom middleware and is not a default `json-server` feature.
**Missing Implementation:**
*   **Shared Development/Testing Environments:** Consider implementing simulated read-only mode in shared environments to protect data integrity during development.

## Mitigation Strategy: [Limit Functionality - CORS Configuration](./mitigation_strategies/limit_functionality_-_cors_configuration.md)

**Description:**
1.  **Identify Allowed Origins:** Determine the specific origins (domains, protocols, ports) that should be permitted to access `json-server`. For local development, this is usually `http://localhost:3000` (or your development application's origin).
2.  **Configure CORS Options:** Use `json-server`'s `--middlewares` flag and a CORS middleware (like `cors` npm package) or configure CORS programmatically if using `json-server` as a module.
3.  **Specify Allowed Origins (Strictly):**  In the CORS configuration, set the `origin` option to a specific array of allowed origins. **Avoid using wildcard (`*`) origins.**
4.  **Restrict Methods and Headers (Optional):**  Further refine CORS by specifying allowed HTTP methods (`methods`) and headers (`allowedHeaders`) if needed, although origin restriction is the most critical.
**Threats Mitigated:**
*   **Unauthorized Access (Medium Severity - Cross-Site Request Forgery (CSRF) Prevention):** CORS helps prevent CSRF attacks from malicious websites by limiting allowed origins.
*   **Data Exposure (Low Severity - Prevents unintended access from untrusted origins):** CORS restricts API access to explicitly allowed origins.
**Impact:**
*   **Unauthorized Access (CSRF):** Medium Risk Reduction - Reduces CSRF risk from untrusted websites.
*   **Data Exposure:** Low Risk Reduction - Provides basic defense against unintended access from untrusted origins.
**Currently Implemented:**
*   **Potentially Partially Implemented:** `json-server` might use default permissive CORS (allowing all origins in development), which is insecure.
**Missing Implementation:**
*   **Development and Testing Environments:** Configure CORS more restrictively, even in development. Specify exact development application origins instead of wildcards. Important for testing across different domains/ports.

