# Mitigation Strategies Analysis for coil-kt/coil

## Mitigation Strategy: [Image Source Validation and Restrictions (Coil-Specific)](./mitigation_strategies/image_source_validation_and_restrictions__coil-specific_.md)

*   **Description:**
    1.  **Create a Custom Fetcher Factory:** Extend Coil's `Fetcher.Factory` to intercept image requests *before* Coil attempts to fetch them. This is the core Coil-specific part.
        ```kotlin
        class ValidatingFetcherFactory : Fetcher.Factory<Uri> {
            override fun create(data: Uri, options: Options, imageLoader: ImageLoader): Fetcher? {
                if (!ImageSourceValidator.isAllowed(data.toString())) {
                    return null // Prevent loading
                    // OR throw InvalidImageSourceException("URL not allowed: $data")
                }
                // Delegate to the default HTTP fetcher if allowed.
                return HttpUriFetcher.Factory().create(data, options, imageLoader)
            }
        }
        ```
    2.  **Integrate into ImageLoader:** Build a custom `ImageLoader` and add the `ValidatingFetcherFactory`. This is how you tell Coil to use your custom validation logic.
        ```kotlin
        val imageLoader = ImageLoader.Builder(context)
            .components {
                add(ValidatingFetcherFactory())
            }
            // ... other configurations ...
            .build()
        ```
    3.  **Use the Custom ImageLoader:** Use this `imageLoader` instance *exclusively* throughout your application when loading images with Coil.  This ensures all image loads go through your validation.

*   **Threats Mitigated:**
    *   **Uncontrolled Resource Consumption (High Severity):** Prevents Coil from loading images from arbitrary, potentially malicious sources.
    *   **Remote Code Execution (RCE) (Critical Severity):** Reduces the attack surface for exploiting decoder vulnerabilities by limiting the origin of images.
    *   **Data Leakage (Medium to High Severity):** Prevents Coil from accessing unauthorized resources.
    *   **Phishing/Malware Delivery (High Severity):** Reduces the risk of Coil loading images from malicious sites.

*   **Impact:**
    *   **All listed threats:** Risk significantly reduced. This is a *fundamental* mitigation for using Coil securely.

*   **Currently Implemented:** Partially implemented. The `ImageSourceValidator` (allowlist logic) exists, but the custom `Fetcher.Factory` and custom `ImageLoader` are *not* implemented. The default `ImageLoader` is being used.

*   **Missing Implementation:** The `ValidatingFetcherFactory` needs to be created and integrated into a custom `ImageLoader`. The application needs to be refactored to use this custom `ImageLoader`.

## Mitigation Strategy: [Secure Image Decoding (Coil Configuration)](./mitigation_strategies/secure_image_decoding__coil_configuration_.md)

*   **Description:**
    1.  **Robust Error Handling (Coil's Listeners):** Within your `ImageRequest` listeners (or a custom `EventListener`), handle `ErrorResult` and other error states gracefully. This is done *directly* within your Coil usage.
        ```kotlin
        val request = ImageRequest.Builder(context)
            .data("https://example.com/image.jpg")
            .listener(
                onError = { _, errorResult ->
                    Log.e("Coil", "Image loading failed: ${errorResult.throwable.message}", errorResult.throwable)
                    // Display a user-friendly error (no sensitive details).
                    // Potentially retry with a backoff strategy.
                }
            )
            .build()
        ```
    2.  **Limit Image Size (Coil's `size` method):** Set maximum dimensions using the `size()` method in your `ImageRequest.Builder`. This is a direct Coil configuration.
        ```kotlin
        val request = ImageRequest.Builder(context)
            .data("https://example.com/image.jpg")
            .size(1024, 768) // Limit dimensions to 1024x768
            .build()
        ```
    3. **Configure Memory and Disk Cache Sizes (Coil's `ImageLoader` Builder):** Set maximum sizes for the memory and disk caches within your `ImageLoader.Builder`.
       ```kotlin
       val imageLoader = ImageLoader.Builder(context)
           .memoryCache {
               MemoryCache.Builder(context)
                   .maxSizeBytes(10 * 1024 * 1024) // 10MB max memory cache
                   .build()
           }
           .diskCache {
               DiskCache.Builder()
                   .directory(context.cacheDir.resolve("image_cache"))
                   .maxSizeBytes(50 * 1024 * 1024) // 50MB max disk cache
                   .build()
           }
           .build()
       ```

*   **Threats Mitigated:**
    *   **Remote Code Execution (RCE) (Critical Severity):** While this doesn't *prevent* RCE, robust error handling helps contain the damage and provides valuable debugging information.
    *   **Denial of Service (DoS) (High Severity):** Limiting image size and handling errors prevents crashes and resource exhaustion.
    *   **Information Disclosure (Medium Severity):** Proper error handling prevents leaking sensitive information through error messages.

*   **Impact:**
    *   **RCE:**  Impact is primarily on containment and debugging, not prevention.
    *   **DoS:** Risk significantly reduced.
    *   **Information Disclosure:** Risk reduced.

*   **Currently Implemented:** Minimal error handling is in place, but it's not comprehensive. Image size limits are *not* implemented. Cache size limits are *not* implemented.

*   **Missing Implementation:** Comprehensive error handling needs to be implemented in `ImageRequest` listeners. Image size limits need to be added to `ImageRequest.Builder` calls. Cache size limits need to be configured in the `ImageLoader.Builder`.

## Mitigation Strategy: [Secure Caching (Coil's Cache Policies)](./mitigation_strategies/secure_caching__coil's_cache_policies_.md)

*   **Description:**
    1.  **Choose Appropriate Cache Policies (Coil's `CachePolicy`):** Use `CachePolicy` strategically *within your `ImageRequest.Builder`*. This is a direct Coil configuration.
        ```kotlin
        val request = ImageRequest.Builder(context)
            .data("https://example.com/sensitive_image.jpg")
            .diskCachePolicy(CachePolicy.READ_ONLY) // Or DISABLED
            .memoryCachePolicy(CachePolicy.DISABLED)
            .build()

        val request2 = ImageRequest.Builder(context) // For less sensitive images
            .data("https://example.com/public_image.jpg")
            .diskCachePolicy(CachePolicy.ENABLED)
            .memoryCachePolicy(CachePolicy.ENABLED)
            .build()
        ```
    2. **Clear the cache programmatically (Coil API):** Use Coil's API to clear the cache.
        ```kotlin
        // In your settings activity or a utility class:
        fun clearImageCache(context: Context) {
            val imageLoader = context.imageLoader // Get your ImageLoader instance
            imageLoader.memoryCache?.clear()
            imageLoader.diskCache?.clear()
        }
        ```

*   **Threats Mitigated:**
    *   **Data Leakage (Medium to High Severity):** Using appropriate cache policies and providing a clearing mechanism reduces the risk.

*   **Impact:**
    *   **Data Leakage:** Risk reduced.

*   **Currently Implemented:** Default cache policies (`CachePolicy.ENABLED`) are being used for all images. There is *no* programmatic cache clearing.

*   **Missing Implementation:** Cache policies need to be reviewed and adjusted on a per-request basis using `ImageRequest.Builder`.  A function to clear the cache using Coil's API needs to be implemented.

## Mitigation Strategy: [Network Security (Coil + OkHttp Configuration)](./mitigation_strategies/network_security__coil_+_okhttp_configuration_.md)

*   **Description:**
    1.  **Implement Certificate Pinning (Using OkHttp with Coil):** This involves configuring OkHttp, which Coil uses under the hood.
        *   **Configure CertificatePinner:**
            ```kotlin
            val certificatePinner = CertificatePinner.Builder()
                .add("example.com", "sha256/your_pin_here") // Replace
                .add("cdn.example.com", "sha256/your_cdn_pin_here")
                .build()
            ```
        *   **Create a Custom OkHttpClient:**
            ```kotlin
            val okHttpClient = OkHttpClient.Builder()
                .certificatePinner(certificatePinner)
                // ... other OkHttp configurations ...
                .build()
            ```
        *   **Use the Custom OkHttpClient with Coil:** This is the crucial Coil-specific step.
            ```kotlin
            val imageLoader = ImageLoader.Builder(context)
                .okHttpClient(okHttpClient) // Tell Coil to use your OkHttpClient
                // ... other ImageLoader configurations ...
                .build()
            ```

*   **Threats Mitigated:**
    *   **Man-in-the-Middle (MitM) Attacks (Critical Severity):** Certificate pinning prevents attackers from using compromised CAs.
    *   **Data Tampering (High Severity):** Ensures image integrity.
    *   **Data Leakage (High Severity):** Prevents interception of image data.

*   **Impact:**
    *   **MitM Attacks:** Risk significantly reduced.
    *   **Data Tampering/Leakage:** Risk significantly reduced.

*   **Currently Implemented:** Certificate pinning is *not* implemented. The default `OkHttpClient` is being used.

*   **Missing Implementation:** A custom `OkHttpClient` with `CertificatePinner` needs to be created and then passed to the `ImageLoader.Builder` using `okHttpClient()`.

