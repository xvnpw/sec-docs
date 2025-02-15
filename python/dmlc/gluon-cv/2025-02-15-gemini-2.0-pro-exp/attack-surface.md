# Attack Surface Analysis for dmlc/gluon-cv

## Attack Surface: [Malicious Pre-trained Models](./attack_surfaces/malicious_pre-trained_models.md)

*   **Description:** An attacker provides a crafted, malicious pre-trained model that, when loaded via `gluon-cv`'s loading functions, executes arbitrary code or causes unexpected behavior. This exploits the user's trust in `gluon-cv`'s model loading capabilities.
*   **How Gluon-CV Contributes:** Gluon-CV's `model_zoo` and associated functions (e.g., `get_model`) provide a streamlined way to load pre-trained models.  This convenience, if misused, directly facilitates the attack.  The attack *relies* on `gluon-cv`'s loading mechanism.
*   **Example:** An attacker hosts a malicious model disguised as a standard `gluon-cv` model (e.g., a modified ResNet).  When a user calls `gluoncv.model_zoo.get_model("resnet50_v1b_malicious", ...)` (thinking it's a legitimate model), the malicious code is executed.
*   **Impact:** Complete system compromise, data exfiltration, arbitrary code execution.
*   **Risk Severity:** **Critical**
*   **Mitigation Strategies:**
    *   **Strict Source Control:** *Only* load models from the official Gluon-CV Model Zoo using the *exact* names provided in the official documentation.  Do *not* load models from any other source, even if they claim to be compatible with `gluon-cv`.  Hardcode the model names and sources whenever possible.
    *   **Checksum Verification:** Before calling `gluoncv.model_zoo.get_model`, obtain the expected SHA-256 hash (or another strong hash) of the model file from the *official* Gluon-CV documentation.  After the model is downloaded (but *before* it's used), calculate its hash and compare it to the expected value.  If they don't match, *immediately* discard the model and raise an alert.  This is crucial because the attacker might try to mimic the official model names.
    *   **Sandboxing (Advanced):**  Isolate the `gluon-cv` model loading and inference process within a container (e.g., Docker) with severely restricted privileges.  This limits the damage even if a malicious model is loaded.  This requires significant expertise in containerization and security.

## Attack Surface: [Model Deserialization Exploits (via Gluon-CV Loading)](./attack_surfaces/model_deserialization_exploits__via_gluon-cv_loading_.md)

*   **Description:** Vulnerabilities in the model deserialization process *within MXNet or Gluon*, triggered *through* `gluon-cv`'s loading functions, are exploited by a crafted, malicious model file. This is a direct attack on the underlying libraries used by `gluon-cv`.
*   **How Gluon-CV Contributes:** `gluon-cv`'s model loading functions (e.g., `gluoncv.model_zoo.get_model`, loading from `.params` files) directly utilize MXNet's and Gluon's deserialization mechanisms.  The vulnerability is *in* MXNet/Gluon, but the attack vector is *through* `gluon-cv`.
*   **Example:** A vulnerability exists in MXNet's handling of a specific layer type during deserialization.  An attacker creates a `.params` file that triggers this vulnerability when loaded using `gluon-cv`'s functions, leading to code execution.
*   **Impact:** Arbitrary code execution, system compromise.
*   **Risk Severity:** **Critical**
*   **Mitigation Strategies:**
    *   **Up-to-Date Dependencies (Primary):**  Ensure that you are using the *absolute latest* patched versions of *both* MXNet and Gluon-CV.  This is the *most critical* mitigation, as it directly addresses the underlying vulnerability.  Subscribe to security advisories for both libraries and apply updates *immediately* upon release.
    *   **Avoid Custom Deserialization (Reinforcement):**  *Exclusively* use `gluon-cv`'s and MXNet's built-in loading functions (e.g., `gluoncv.model_zoo.get_model`, `mxnet.gluon.nn.SymbolBlock.imports`).  *Never* implement any custom code to load or deserialize model files.
    *   **Sandboxing (as above):**  As with malicious models, sandboxing the entire `gluon-cv` model loading and inference process provides a strong layer of defense, even if a deserialization vulnerability is exploited.

## Attack Surface: [Denial of Service (DoS) via Input to Gluon-CV Models](./attack_surfaces/denial_of_service__dos__via_input_to_gluon-cv_models.md)

*   **Description:** An attacker sends crafted input data to a model *loaded through Gluon-CV*, causing excessive resource consumption and a denial-of-service. The attack exploits the model's processing logic, accessed *via* `gluon-cv`.
*   **How Gluon-CV Contributes:** The attack targets a model *obtained and used through* `gluon-cv`. While the vulnerability might be in the model's architecture or implementation (potentially within MXNet), the attack vector is the input to a `gluon-cv` loaded model.
*   **Example:** An attacker sends extremely large images to an image classification model loaded using `gluoncv.model_zoo.get_model`, causing the application to exhaust memory.
*   **Impact:** Application unavailability, resource exhaustion.
*   **Risk Severity:** **High**
*   **Mitigation Strategies:**
    *   **Strict Input Validation (before Gluon-CV call):** *Before* passing any data to a `gluon-cv` loaded model, rigorously validate and sanitize the input.  Enforce strict limits on image dimensions, data types, and other relevant parameters.  Reject any input that exceeds these limits. This is *crucial* to perform *before* any `gluon-cv` function calls.
    *   **Resource Limits (on the process using Gluon-CV):**  Set resource limits (CPU time, memory, GPU memory) on the process or container that is *using* `gluon-cv`. This prevents a single inference call from consuming all available resources.
    *   **Timeouts (around Gluon-CV calls):**  Wrap calls to `gluon-cv` model inference functions with timeouts.  If an inference takes longer than a predefined threshold, terminate it to prevent resource exhaustion.

