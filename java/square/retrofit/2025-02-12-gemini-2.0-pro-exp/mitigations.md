# Mitigation Strategies Analysis for square/retrofit

## Mitigation Strategy: [Secure Deserialization Practices (Retrofit Converter Configuration)](./mitigation_strategies/secure_deserialization_practices__retrofit_converter_configuration_.md)

**Strategy:** Secure Deserialization Practices (Retrofit Converter Configuration)

*   **Description:**
    1.  **Choose a Secure Deserializer:** When configuring Retrofit, select a well-maintained and actively patched JSON deserialization library (e.g., Moshi, or the latest versions of Gson/Jackson) *as your converter*.
    2.  **Configure the Converter (if necessary):**  If using Gson, *avoid* using `GsonBuilder().enableComplexMapKeySerialization()` unless absolutely required, as this can introduce vulnerabilities.  For other converters, review their documentation for any security-related configuration options.
    3.  **Use with Retrofit:** Integrate the chosen and configured converter with Retrofit using `addConverterFactory()`.
        ```java
        // Example using Gson (but be mindful of security considerations)
        Gson gson = new GsonBuilder()
            // ... other Gson configurations ...
            .create();

        Retrofit retrofit = new Retrofit.Builder()
            .baseUrl("https://yourdomain.com/")
            .addConverterFactory(GsonConverterFactory.create(gson)) // Use the configured Gson instance
            .build();

        // Example using Moshi (generally preferred for security)
        Moshi moshi = new Moshi.Builder()
            // ... other Moshi configurations ...
            .build();

        Retrofit retrofit = new Retrofit.Builder()
            .baseUrl("https://yourdomain.com/")
            .addConverterFactory(MoshiConverterFactory.create(moshi)) // Use the configured Moshi instance
            .build();
        ```
    4.  **Define Strict Data Models:** Create precise Java/Kotlin classes that match the expected structure of your JSON responses. Avoid generic types. This is crucial for type-safe deserialization. This is *used by* Retrofit, but not directly *configured in* Retrofit.
    5. **Validate Deserialized Data:** Although not directly a Retrofit configuration, *after* Retrofit deserializes the data using the converter, perform additional validation. This is crucial, but separate from Retrofit's direct configuration.

*   **Threats Mitigated:**
    *   **Remote Code Execution (RCE) via Deserialization:** (Severity: Critical) - Attackers inject malicious objects.
    *   **Data Tampering:** (Severity: High) - Attackers modify JSON data.
    *   **Denial of Service (DoS):** (Severity: Medium) - Malformed JSON causing resource exhaustion.

*   **Impact:**
    *   **RCE:** Risk significantly reduced by choosing a secure converter and configuring it safely.
    *   **Data Tampering:** Risk reduced by using strict data models (although validation is still key).
    *   **DoS:** Risk partially mitigated by using a robust deserializer.

*   **Currently Implemented:**
    *   Example: Using `MoshiConverterFactory` with Moshi 1.15.0.
    *   Example: Converter factory configured in `NetworkModule.java`.

*   **Missing Implementation:**
    *   Example:  Need to review all Retrofit service interfaces to ensure they use appropriate, specific data models.

## Mitigation Strategy: [Secure Handling of Sensitive Data (Retrofit Annotations)](./mitigation_strategies/secure_handling_of_sensitive_data__retrofit_annotations_.md)

**Strategy:** Secure Handling of Sensitive Data (Retrofit Annotations)

*   **Description:**
    1.  **Identify Sensitive Data:** Determine which data requires special handling (API keys, tokens, PII).
    2.  **Use `@Header` for Authentication:**  Pass API keys and tokens in HTTP headers using the `@Header` annotation in your Retrofit interface definitions.
        ```java
        interface ApiService {
            @GET("users")
            Call<List<User>> getUsers(@Header("Authorization") String token); // Use @Header

            @POST("login")
            Call<LoginResponse> login(@Body LoginRequest request); // Use @Body for request body
        }
        ```
    3.  **Use `@Field`, `@FieldMap`, `@Part`, and `@Body` Appropriately:**
        *   `@Field` and `@FieldMap`: For `application/x-www-form-urlencoded` data (typically POST requests).
        *   `@Part`: For `multipart/form-data` (e.g., file uploads).
        *   `@Body`: For sending a Java object as the request body (e.g., JSON).  Use this for sensitive data that should be in the body, and combine it with POST/PUT/PATCH.
    4.  **Avoid `@Query` and `@Path` for Sensitive Data:** Do *not* use `@Query` (for query parameters in the URL) or `@Path` (for path parameters in the URL) to pass sensitive data.
    5.  **Choose Appropriate HTTP Methods:** Use POST, PUT, or PATCH for requests that send sensitive data in the body. Avoid GET for sending sensitive data. This isn't a *direct* Retrofit annotation, but it's how you *use* Retrofit.

*   **Threats Mitigated:**
    *   **Data Exposure via URL Logging:** (Severity: High) - Sensitive data in URLs is logged.
    *   **Data Exposure via Request Body Logging (if misused):** (Severity: High) - Improper use of annotations could lead to sensitive data being logged if logging is not carefully managed.

*   **Impact:**
    *   **Data Exposure via Logging:** Risk significantly reduced by using `@Header` and appropriate HTTP methods, and by *avoiding* `@Query` and `@Path` for sensitive data.

*   **Currently Implemented:**
    *   Example: `@Header("Authorization")` used in `ApiService.java`.
    *   Example: `@Body` used for POST requests with sensitive data.

*   **Missing Implementation:**
    *   Example:  Review all Retrofit interface methods to ensure consistent and correct use of annotations.
    *   Example: One endpoint incorrectly uses `@Query` for a user ID; this should be changed to `@Path` or included in the request body.

## Mitigation Strategy: [Robust Error Handling (Retrofit `Call` and `Response`)](./mitigation_strategies/robust_error_handling__retrofit__call__and__response__.md)

**Strategy:** Robust Error Handling (Retrofit `Call` and `Response`)

*   **Description:**
    1.  **Use `Call.execute()` or `Call.enqueue()`:**  Use Retrofit's `Call` object methods to make requests:
        *   `execute()`: For synchronous requests (blocks the current thread).
        *   `enqueue()`: For asynchronous requests (uses a callback).
    2.  **Handle `Response`:**  Check the `Response` object:
        *   `response.isSuccessful()`:  Indicates an HTTP status code in the 200-299 range.
        *   `response.body()`:  Gets the deserialized response body (if successful).
        *   `response.errorBody()`:  Gets the error body (if not successful).  *Do not expose this directly to users.*
        *   `response.code()`: Gets the HTTP status code.
    3.  **Catch Exceptions:** Wrap Retrofit calls in `try-catch` blocks to handle:
        *   `IOException`: Network errors.
        *   `RuntimeException`: Other runtime errors (including potential deserialization errors).
    4.  **Provide User-Friendly Messages:** Display generic error messages to users, *not* raw error messages from `response.errorBody()`.
    5. **Consider Custom `CallAdapter.Factory` (Advanced):** For more advanced error handling, you can create a custom `CallAdapter.Factory` to wrap Retrofit's `Call` objects and provide a consistent error handling mechanism across your application. This allows you to intercept and transform errors before they reach your application code. This is a more advanced, but directly Retrofit-related, technique.

*   **Threats Mitigated:**
    *   **Information Disclosure via Error Messages:** (Severity: Medium) - Attackers gain insights from error messages.

*   **Impact:**
    *   **Information Disclosure:** Risk significantly reduced by not exposing raw error messages.

*   **Currently Implemented:**
    *   Example: `try-catch` blocks used around `Call.execute()` in `UserRepository.java`.

*   **Missing Implementation:**
    *   Example:  Raw error messages from `response.errorBody()` are sometimes shown to users.
    *   Example: No custom `CallAdapter.Factory` is used for centralized error handling.

