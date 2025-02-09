# Threat Model Analysis for woltapp/blurhash

## Threat: [Excessive Detail Reconstruction](./threats/excessive_detail_reconstruction.md)

*   **Description:** An attacker analyzes a Blurhash string, potentially generated with a high number of components, or compares multiple Blurhashes of similar images. They use specialized tools or techniques to reconstruct a more detailed approximation of the original image than intended, revealing sensitive visual information. The attacker might use publicly available or custom-built de-blurring tools.
*   **Impact:**
    *   **Privacy Violation:** Sensitive details of the original image are revealed, potentially exposing personal information, confidential data, or other private content.
    *   **Reputational Damage:** If the application handles sensitive images, a successful reconstruction could damage the application's reputation and user trust.
    *   **Regulatory Non-compliance:** Depending on the nature of the data and applicable regulations (e.g., GDPR, CCPA), this could lead to legal and financial penalties.
*   **Affected Blurhash Component:**
    *   `encode` function (specifically, the `xComponents` and `yComponents` parameters).
    *   The resulting Blurhash string itself.
*   **Risk Severity:** High (if sensitive images are used)
*   **Mitigation Strategies:**
    *   **Minimize Components:** Use the absolute minimum number of `xComponents` and `yComponents` required for the desired level of blur. Conduct thorough testing to determine this minimum.
    *   **Consistent Component Use:** Apply the same `xComponents` and `yComponents` values consistently across all images of a similar type and sensitivity level.
    *   **Pre-processing Downsampling:** Downsample the original image to a very low resolution *before* encoding it with Blurhash. This limits the initial detail available.
    *   **Privacy Impact Assessment:** Conduct a formal privacy impact assessment to evaluate the risks associated with using Blurhash for the specific image types.

## Threat: [Encoding-Based Denial of Service (Server-Side)](./threats/encoding-based_denial_of_service__server-side_.md)

*   **Description:** An attacker crafts a malicious image (e.g., extremely large, high-frequency patterns, specific color palettes) and uploads it to the server. This image is designed to cause the Blurhash `encode` function to consume excessive CPU resources or memory, leading to a denial-of-service condition on the server. The attacker repeatedly uploads such images to amplify the effect.
*   **Impact:**
    *   **Service Unavailability:** The application becomes unresponsive or unavailable to legitimate users.
    *   **Resource Exhaustion:** Server resources (CPU, memory) are depleted, potentially affecting other applications or services running on the same server.
    *   **Financial Loss:** If the application is critical for business operations, downtime can lead to financial losses.
*   **Affected Blurhash Component:**
    *   `encode` function.
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   **Strict Image Size Limits:** Enforce strict limits on the dimensions (width, height) and file size of uploaded images *before* they reach the `encode` function.
    *   **Resource Limits (Encoding):** Implement resource limits (CPU time, memory allocation) for the `encode` function. Terminate the process if these limits are exceeded.
    *   **Rate Limiting (Uploads):** Implement rate limiting on the image upload endpoint to prevent an attacker from submitting a large number of malicious images quickly.
    *   **Input Validation (Image Format):** Validate the image format and basic structure *before* passing it to the `encode` function. Reject malformed or suspicious images.
    * **Timeout:** Implement timeout for encoding process.

