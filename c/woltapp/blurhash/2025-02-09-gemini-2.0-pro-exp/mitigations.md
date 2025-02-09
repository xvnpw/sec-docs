# Mitigation Strategies Analysis for woltapp/blurhash

## Mitigation Strategy: [Salt the Input Image](./mitigation_strategies/salt_the_input_image.md)

*   **Description:**
    1.  **Generate a Secret Key:** Create a cryptographically secure random key (e.g., using a secure random number generator). This key should be stored securely on the server and *never* exposed to the client.  Consider using a key management system.
    2.  **Image-Specific Salt:** For each image, generate a unique, random salt. This could be a random string or a small, random image.  The key is that it's unique *per image*.
    3.  **Combine Salt and Image:** Before encoding with BlurHash, combine the salt with the original image.  Several methods are possible:
        *   **Overlay:** If the salt is a small image, overlay it onto the original image at a very low opacity (e.g., 1-2%).  Ensure the overlay position is also randomized slightly.
        *   **Pixel Modification:** If the salt is a string, use it (along with the secret key) to derive a set of pixel coordinates and color adjustments.  Apply these subtle changes to the original image.  For example, you could use a keyed hash function (like HMAC) to generate pseudo-random offsets and color deltas.
        *   **Watermarking (Advanced):** Embed the salt as an invisible watermark using a robust watermarking algorithm. This is the most complex but potentially most secure option.
    4.  **Encode with BlurHash:** Encode the *modified* image using the BlurHash library.
    5.  **Store Salt Metadata:** Store the image-specific salt *securely* alongside the image metadata (e.g., in a database).  This is crucial for consistently generating the same salted BlurHash for the same image.  *Do not* store the secret key with the image metadata.
    6.  **Consistent Application:** Ensure that this salting process is applied *consistently* whenever a BlurHash is generated for an image.

*   **Threats Mitigated:**
    *   **Information Leakage through Predictable Hashes (Low Severity):** Significantly reduces the risk.  The salt makes it computationally infeasible for an attacker to pre-compute BlurHashes and compare them.
    *   **Reverse Engineering of Image Features (Low Severity):** Provides some additional protection, as the salt subtly alters the image features encoded in the hash.

*   **Impact:**
    *   **Information Leakage:** Risk reduced from Low to Very Low.
    *   **Reverse Engineering:** Risk reduced from Low to Very Low.

*   **Currently Implemented:**
    *   Example:  "Not Implemented.  The BlurHash encoding is currently done directly on the original image without any pre-processing."

*   **Missing Implementation:**
    *   "Image upload and processing pipeline (server-side).  Specifically, the function responsible for generating the BlurHash needs to be modified to include the salting steps."
    * "Need to add a secure key management system."
    * "Need to add database field to store image-specific salt."

## Mitigation Strategy: [Limit Component Count](./mitigation_strategies/limit_component_count.md)

*   **Description:**
    1.  **Encoding Function:** Locate the code where the `blurhash.encode()` function (or equivalent) is called.
    2.  **Component Parameters:** The `encode()` function typically takes `xComponents` and `yComponents` parameters (or similar), which control the level of detail in the BlurHash.
    3.  **Reduce Components:** Experiment with lower values for these parameters (e.g., 3x3, 4x3).  The default is often 4x3.
    4.  **Visual Assessment:**  Carefully evaluate the visual quality of the resulting BlurHashes.  Ensure they still provide an acceptable placeholder experience.
    5.  **Balance:** Find a balance between visual fidelity and the amount of information encoded in the hash.  Lower component counts reduce information leakage but also make the placeholder less representative.

*   **Threats Mitigated:**
    *   **Information Leakage through Predictable Hashes (Low Severity):** Slightly reduces the risk by reducing the complexity of the hash.
    *   **Reverse Engineering of Image Features (Low Severity):** Slightly reduces the risk by limiting the amount of detail encoded.

*   **Impact:**
    *   **Information Leakage:** Risk reduction is minimal (Low to slightly lower than Low).
    *   **Reverse Engineering:** Risk reduction is minimal (Low to slightly lower than Low).

*   **Currently Implemented:**
    *   Example: "Partially Implemented. The default component count (4x3) is currently used.  We have experimented with lower values, but haven't yet committed to a specific lower setting."

*   **Missing Implementation:**
    *   "Need to finalize the decision on the optimal component count based on visual quality and security considerations. Update the encoding function accordingly."

