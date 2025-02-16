# Attack Tree Analysis for norman/friendly_id

Objective: Gain unauthorized access to resources or information, or cause denial of service, by exploiting vulnerabilities or misconfigurations related to the `friendly_id` gem.

## Attack Tree Visualization

```
                                      Gain Unauthorized Access/DoS via friendly_id
                                                      |
                      ---------------------------------------------------------------------------------
                      |                                                                               |
              1. Slug Collision/Prediction                                                 3.  Configuration/Implementation Errors
                      |                                                                               |
      ---------------------------------                                                       ---------------------------------
      |               |                                                                       |               |               |
1.1  Brute-Force 1.2  Dictionary                                                           3.1  Use of      3.2  Insecure    3.3 Insufficient
     Slugs        Attack on                                                                    `find`        Slug         Length/
 --HIGH RISK-->   Short Slugs                                                                  directly      Generation     Complexity
      |          --HIGH RISK-->                                                               [CRITICAL]   (e.g.,         Checks
      |                                                                                     (bypassing    predictable  --HIGH RISK-->
      |                                                                                      friendly_id)  sequence)
      |
      |
(If short/
simple slugs)
```

## Attack Tree Path: [1. Slug Collision/Prediction (High-Risk Path)](./attack_tree_paths/1__slug_collisionprediction__high-risk_path_.md)

*   **Overall Description:** The attacker attempts to guess or create a slug that matches an existing resource's slug, leading to unauthorized access.  This is particularly dangerous if the application allows short, simple, or predictable slugs.

## Attack Tree Path: [1.1 Brute-Force Slugs (High Risk if short/simple slugs are allowed)](./attack_tree_paths/1_1_brute-force_slugs__high_risk_if_shortsimple_slugs_are_allowed_.md)

*   **Description:** The attacker systematically tries many different slug combinations until they find a valid one.
*   **Likelihood:** High to Very High if short/simple slugs are allowed; Very Low with default `friendly_id` settings (UUIDs).
*   **Impact:** Medium to High (Unauthorized access to resources, data leakage).
*   **Effort:** Low to Medium if short/simple slugs are allowed; Very High with default settings.
*   **Skill Level:** Low (Basic scripting knowledge).
*   **Detection Difficulty:** Low without rate limiting (many failed requests); Medium to High with rate limiting.

## Attack Tree Path: [1.2 Dictionary Attack on Short Slugs (High Risk if short/simple, word-based slugs are allowed)](./attack_tree_paths/1_2_dictionary_attack_on_short_slugs__high_risk_if_shortsimple__word-based_slugs_are_allowed_.md)

*   **Description:** The attacker uses a list of common words, phrases, or names to try and guess valid slugs.
*   **Likelihood:** High if short, simple, word-based slugs are allowed; Very Low with default settings.
*   **Impact:** Medium to High (Unauthorized access, data leakage).
*   **Effort:** Low (Readily available wordlists).
*   **Skill Level:** Very Low (Basic scripting).
*   **Detection Difficulty:** Low without rate limiting; Medium to High with rate limiting.

## Attack Tree Path: [3. Configuration/Implementation Errors (High-Risk Path and Critical Node)](./attack_tree_paths/3__configurationimplementation_errors__high-risk_path_and_critical_node_.md)

*   **Overall Description:** Mistakes made by the developer when implementing or configuring `friendly_id` can create significant vulnerabilities.

## Attack Tree Path: [3.1 Use of `find` directly (bypassing `friendly_id`) [CRITICAL]](./attack_tree_paths/3_1_use_of__find__directly__bypassing__friendly_id____critical_.md)

*   **Description:** The developer uses the standard ActiveRecord `find` method with a numeric ID *instead* of `friendly_id`'s `friendly.find` (or equivalent). This completely bypasses the slug lookup and its security benefits.
*   **Likelihood:** Medium (Common mistake, especially for developers new to `friendly_id`).
*   **Impact:** Very High (Complete bypass of slug-based access control; direct access to resources via numeric IDs).
*   **Effort:** Very Low (Just knowing the numeric ID).
*   **Skill Level:** Very Low.
*   **Detection Difficulty:** Very High (Appears as completely legitimate traffic; no indication that `friendly_id` is being bypassed).

## Attack Tree Path: [3.2 Insecure Slug Generation (e.g., predictable sequence) (High Risk)](./attack_tree_paths/3_2_insecure_slug_generation__e_g___predictable_sequence___high_risk_.md)

*   **Description:** The developer overrides the default slug generation with a custom method that produces predictable slugs (e.g., a simple counter or a weak random number generator).
*   **Likelihood:** Low to Medium (Requires overriding the default, secure slug generation).
*   **Impact:** High (Predictable access to resources).
*   **Effort:** Medium (Requires understanding and implementing a custom slug generation method).
*   **Skill Level:** Medium (Requires some programming knowledge).
*   **Detection Difficulty:** High (Difficult to distinguish from legitimate requests).

## Attack Tree Path: [3.3 Insufficient Length/Complexity Checks (High Risk)](./attack_tree_paths/3_3_insufficient_lengthcomplexity_checks__high_risk_.md)

*   **Description:** The developer allows very short or simple slugs, making brute-force or dictionary attacks much easier. This directly enables attack vectors 1.1 and 1.2.
*   **Likelihood:** Low to Medium (Requires overriding default settings or not implementing proper validation).
*   **Impact:** Medium to High (Makes brute-force and dictionary attacks easier).
*   **Effort:** Very Low (For the attacker, if the vulnerability exists).
*   **Skill Level:** Very Low (For the attacker).
*   **Detection Difficulty:** Medium (Similar to brute-force and dictionary attack detection).

