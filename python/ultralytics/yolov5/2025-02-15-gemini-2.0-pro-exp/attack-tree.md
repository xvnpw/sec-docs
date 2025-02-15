# Attack Tree Analysis for ultralytics/yolov5

Objective: [[Attacker's Goal: Cause Misclassification, Data Leak, or DoS]]

## Attack Tree Visualization

[[Attacker's Goal: Cause Misclassification, Data Leak, or DoS]]
        /
       /
[[1. Degrade Model Performance/Accuracy]]
/===============
/
[[1.1 Adversarial Examples]]
/=====\
/       \
[[1.1.1 Crafted Input]] [[1.1.2 Evasion (FGSM, PGD, etc.)]]
                        [[(FGSM)]]

## Attack Tree Path: [Attacker's Goal: Cause Misclassification, Data Leak, or DoS](./attack_tree_paths/attacker's_goal_cause_misclassification__data_leak__or_dos.md)

*   **`[[Attacker's Goal: Cause Misclassification, Data Leak, or DoS]]`**
    *   **Description:** The ultimate objective of the attacker targeting the YOLOv5-based application. This encompasses causing the model to incorrectly classify objects, revealing sensitive information that the model has learned or been exposed to, or rendering the application unavailable through denial-of-service.
    *   **Likelihood:** N/A (This is the goal, not an attack step)
    *   **Impact:** Very High
    *   **Effort:** N/A
    *   **Skill Level:** N/A
    *   **Detection Difficulty:** N/A

## Attack Tree Path: [1. Degrade Model Performance/Accuracy](./attack_tree_paths/1__degrade_model_performanceaccuracy.md)

*   **`[[1. Degrade Model Performance/Accuracy]]`**
    *   **Description:** This category encompasses attacks that aim to reduce the effectiveness and reliability of the YOLOv5 model.  The attacker's aim is to make the model produce incorrect or unreliable results.
    *   **Likelihood:** High
    *   **Impact:** High to Very High
    *   **Effort:** Varies (Low to High, depending on the specific attack)
    *   **Skill Level:** Varies (Intermediate to Advanced)
    *   **Detection Difficulty:** Varies (Medium to Very Hard)

## Attack Tree Path: [1.1 Adversarial Examples](./attack_tree_paths/1_1_adversarial_examples.md)

*   **`[[1.1 Adversarial Examples]]`**
    *   **Description:**  This involves crafting or modifying inputs to the model in a way that is specifically designed to cause misclassification. These modifications are often imperceptible to the human eye.
    *   **Likelihood:** Very High
    *   **Impact:** High to Very High
    *   **Effort:** Low to Medium
    *   **Skill Level:** Intermediate
    *   **Detection Difficulty:** Medium to Hard

## Attack Tree Path: [1.1.1 Crafted Input](./attack_tree_paths/1_1_1_crafted_input.md)

*   **`[[1.1.1 Crafted Input]]`**
    *   **Description:** Creating a completely new, malicious input image from scratch, designed to be misclassified by the YOLOv5 model. This might involve generating an image that resembles random noise but is classified as a specific object by the model.
    *   **Likelihood:** High
    *   **Impact:** Medium to High
    *   **Effort:** Low to Medium
    *   **Skill Level:** Intermediate
    *   **Detection Difficulty:** Medium to Hard

## Attack Tree Path: [1.1.2 Evasion (FGSM, PGD, etc.)](./attack_tree_paths/1_1_2_evasion__fgsm__pgd__etc__.md)

*   **`[[1.1.2 Evasion (FGSM, PGD, etc.)]]`**
    *   **Description:**  Subtly modifying a *legitimate* input image using techniques like Fast Gradient Sign Method (FGSM) or Projected Gradient Descent (PGD). These modifications are designed to be minimal, often invisible to humans, but cause the model to confidently misclassify the image.
    *   **Likelihood:** Very High
    *   **Impact:** High to Very High
    *   **Effort:** Low
    *   **Skill Level:** Intermediate
    *   **Detection Difficulty:** Hard

## Attack Tree Path: [(FGSM)](./attack_tree_paths/_fgsm_.md)

*    **`[[(FGSM)]]`**
    *   **Description:** Fast Gradient Sign Method. A specific, widely used, and efficient technique for generating adversarial examples. It works by calculating the gradient of the loss function with respect to the input image and then adding a small perturbation in the direction of that gradient.
    *   **Likelihood:** Very High
    *   **Impact:** High to Very High
    *   **Effort:** Low
    *   **Skill Level:** Intermediate
    *   **Detection Difficulty:** Hard

