# Threat Model Analysis for keras-team/keras

## Threat: [Deserialization Vulnerability via Malicious Saved Model](./threats/deserialization_vulnerability_via_malicious_saved_model.md)

*   **Threat:** Deserialization Vulnerability via Malicious Saved Model
    *   **Description:** An attacker crafts a malicious Keras model file (e.g., in HDF5 or SavedModel format) containing embedded code or instructions that exploit deserialization vulnerabilities in the `keras.models.load_model()` function. When the application uses this function to load the malicious model, the embedded code is executed.
    *   **Impact:** Remote code execution on the server or client loading the model, potentially allowing the attacker to gain full control of the system, steal sensitive data, or launch further attacks.
    *   **Affected Keras Component:** `keras.models.load_model()` function.
    *   **Risk Severity:** Critical
    *   **Mitigation Strategies:**
        *   **Crucially, only load models from trusted and verified sources.**
        *   Implement integrity checks (e.g., cryptographic signatures) on saved model files before loading them with `keras.models.load_model()`.
        *   Keep Keras and its backend dependencies (like TensorFlow) updated to the latest versions, as these often include patches for deserialization vulnerabilities in serialization libraries used by Keras.
        *   Consider using safer serialization methods if available and practical for your use case, although Keras's primary save/load mechanisms rely on formats prone to these issues.
        *   Implement sandboxing or containerization for processes that load potentially untrusted models using `keras.models.load_model()`.

