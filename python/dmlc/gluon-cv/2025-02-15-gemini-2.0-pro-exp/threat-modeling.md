# Threat Model Analysis for dmlc/gluon-cv

## Threat: [Adversarial Example Input (Classification)](./threats/adversarial_example_input__classification_.md)

*   **Description:** An attacker crafts a visually imperceptible perturbation to an input image. This perturbation, while unnoticeable to a human, causes a Gluon-CV image classification model to misclassify the image with high confidence. The attacker might, for example, change a "stop sign" image slightly so the model classifies it as a "speed limit" sign.
*   **Impact:** Incorrect classification results, leading to application malfunction. In a security-critical system (e.g., autonomous driving), this could have severe consequences. In less critical systems, it could lead to incorrect data processing or user frustration.
*   **Affected Gluon-CV Component:** `gluoncv.model_zoo` (pre-trained classification models), any custom model trained using Gluon-CV's training utilities (e.g., `gluoncv.data`, `gluoncv.utils.train_image_classification`). Specifically, the forward pass (inference) of any classification model.
*   **Risk Severity:** High to Critical (depending on the application).
*   **Mitigation Strategies:**
    *   Implement adversarial training using techniques like FGSM (Fast Gradient Sign Method) or PGD (Projected Gradient Descent). Gluon-CV's training loop can be modified to include adversarial example generation.
    *   Employ defensive distillation to make the model more robust to small input perturbations.
    *   Use input preprocessing techniques like JPEG compression or random resizing, which can sometimes disrupt adversarial perturbations (though this is not a foolproof defense).
    *   Monitor model confidence scores and reject predictions with low confidence.

## Threat: [Adversarial Example Input (Object Detection)](./threats/adversarial_example_input__object_detection_.md)

*   **Description:** Similar to the classification attack, but targeting object detection models. The attacker crafts an image where objects are either misdetected (false negatives), incorrectly classified, or spurious objects are detected (false positives). For example, making a car undetectable to a traffic monitoring system.
*   **Impact:** Failure to detect objects, incorrect object localization, or detection of non-existent objects. This can lead to security breaches (e.g., bypassing surveillance) or operational failures.
*   **Affected Gluon-CV Component:** `gluoncv.model_zoo` (pre-trained object detection models like SSD, YOLO, Faster R-CNN), custom object detection models trained with Gluon-CV. Specifically, the model's prediction/inference stage.
*   **Risk Severity:** High to Critical (depending on the application).
*   **Mitigation Strategies:**
    *   Adversarial training specifically tailored for object detection models. This is more complex than classification adversarial training.
    *   Use of robust loss functions during training that are less sensitive to adversarial perturbations.
    *   Input preprocessing and augmentation, similar to classification, but with consideration for how it affects bounding box predictions.
    *   Ensemble methods: Combine predictions from multiple object detection models.

## Threat: [Training Data Poisoning (Fine-tuning)](./threats/training_data_poisoning__fine-tuning_.md)

*   **Description:** An attacker gains access to the dataset used to fine-tune a Gluon-CV model. They introduce subtly mislabeled images or images designed to degrade the model's performance or introduce specific biases. For example, adding images of stop signs labeled as "yield" signs.
*   **Impact:** Reduced model accuracy, biased predictions, or complete model failure. The attacker could subtly control the model's behavior.
*   **Affected Gluon-CV Component:** `gluoncv.data` (datasets and data loaders), custom datasets used with Gluon-CV's training utilities. The entire training pipeline is affected.
*   **Risk Severity:** High.
*   **Mitigation Strategies:**
    *   Strict data validation and sanitization of the training dataset. This includes checking for label correctness and image integrity.
    *   Data provenance: Maintain a clear record of the origin and history of all training data.
    *   Outlier detection: Use statistical methods to identify and remove anomalous data points from the training set.
    *   Manual review of a subset of the training data, especially if sourced from untrusted sources.

## Threat: [Denial of Service (Resource Exhaustion) via crafted inputs to Gluon-CV models](./threats/denial_of_service__resource_exhaustion__via_crafted_inputs_to_gluon-cv_models.md)

*   **Description:** An attacker sends a large number of very large or computationally complex images *specifically designed to maximize the processing time of the Gluon-CV model*. This is distinct from a generic DoS; the attacker leverages knowledge of the model's architecture or implementation details (e.g., a specific layer that is slow to process certain types of inputs) to craft inputs that are particularly expensive to process.
*   **Impact:** Application downtime, denial of service to legitimate users. The attacker can cause significantly more damage with fewer requests than a generic DoS attack.
*   **Affected Gluon-CV Component:** Any Gluon-CV component that performs image processing or model inference. Specifically, functions that handle image loading, preprocessing, and model prediction. The attacker targets specific layers or operations within the model.
*   **Risk Severity:** High.
*   **Mitigation Strategies:**
    *   Strict input validation: Limit the size and dimensions of input images. *Also, implement checks for image complexity features that are known to be computationally expensive for the specific Gluon-CV model being used.*
    *   Resource quotas: Limit the amount of CPU, GPU, and memory that can be used by a single request or user.
    *   Timeouts: Set *very strict* timeouts for model inference, specifically tailored to the expected processing time of the Gluon-CV model.
    *   Profiling: Profile the Gluon-CV model's performance to identify potential bottlenecks and areas that are vulnerable to resource exhaustion attacks.
    *   Asynchronous processing and Load Balancing (as before).

