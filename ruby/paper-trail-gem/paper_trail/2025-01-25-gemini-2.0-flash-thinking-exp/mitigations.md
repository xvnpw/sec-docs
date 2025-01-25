# Mitigation Strategies Analysis for paper-trail-gem/paper_trail

## Mitigation Strategy: [Attribute-Level Data Masking](./mitigation_strategies/attribute-level_data_masking.md)

*   **Mitigation Strategy:** Attribute-Level Data Masking
*   **Description:**
    1.  **Identify Sensitive Attributes:** Review your application models and pinpoint attributes that hold sensitive data (e.g., passwords, credit card numbers, social security numbers, personal addresses, etc.).
    2.  **Utilize `paper_trail` Configuration Options:** In your model definitions, employ `paper_trail`'s built-in configuration options to manage attribute tracking.
        *   **`skip_attributes`:**  Use this option to explicitly prevent specific attributes from being recorded in the audit logs. For example, to exclude `credit_card_number` from the `User` model's audit trail:
            ```ruby
            class User < ApplicationRecord
              has_paper_trail skip: [:credit_card_number]
            end
            ```
        *   **`only`:** Use this option to specify that *only* the listed attributes should be tracked, effectively excluding all others. For instance, to only track `name` and `email` changes for the `User` model:
            ```ruby
            class User < ApplicationRecord
              has_paper_trail only: [:name, :email]
            end
            ```
    3.  **Verification:** After configuring these options, thoroughly test your application. Verify that the designated sensitive attributes are indeed *not* being logged in the `versions` table when records are created, updated, or destroyed.
*   **Threats Mitigated:**
    *   **Sensitive Data Exposure in Audit Logs (High Severity):**  The risk of inadvertently logging sensitive data in plain text within the audit logs, making it vulnerable if the logs are compromised.
*   **Impact:**
    *   **Sensitive Data Exposure in Audit Logs (High Impact):**  Significantly reduces the risk by directly preventing sensitive data from being stored in the audit logs via PaperTrail's configuration.
*   **Currently Implemented:** Partially implemented in `app/models/user.rb` and `app/models/order.rb`. Credit card numbers are skipped in `Order` model using `skip_attributes`.
*   **Missing Implementation:** Missing for `User` model attributes like `password_digest`, `address`, and potentially other models containing personal identifiable information (PII) like `Customer` and `Profile`. Requires a comprehensive review across all models to identify and configure sensitive attributes for skipping or selective tracking.

## Mitigation Strategy: [Selective Auditing of Models and Attributes using PaperTrail Configuration](./mitigation_strategies/selective_auditing_of_models_and_attributes_using_papertrail_configuration.md)

*   **Mitigation Strategy:** Selective Auditing of Models and Attributes using PaperTrail Configuration
*   **Description:**
    1.  **Assess Audit Requirements:**  Carefully evaluate your application's security, compliance, and operational needs to determine precisely which models and attributes necessitate audit logging.
    2.  **Disable PaperTrail for Unnecessary Models:** If certain models do not handle critical data or are not relevant for audit trails, completely disable PaperTrail for those models to reduce logging overhead. This can be done by simply not including `has_paper_trail` in the model definition.
    3.  **Utilize `only` or `skip` Options for Attributes (within PaperTrail enabled models):** For models where PaperTrail is enabled, refine the scope of auditing at the attribute level. Use the `only` or `skip` options (as described in "Attribute-Level Data Masking") to ensure only essential attributes are tracked.
        *   Example: To audit only `name` and `status` attributes of the `Product` model:
            ```ruby
            class Product < ApplicationRecord
              has_paper_trail only: [:name, :status]
            end
            ```
    4.  **Regular Review of Auditing Scope:** Periodically re-examine your auditing requirements. As your application evolves, the criticality of auditing certain models or attributes may change. Adjust PaperTrail configurations accordingly to maintain an efficient and relevant audit trail.
*   **Threats Mitigated:**
    *   **Performance Degradation due to Excessive Logging (Low Severity):**  Auditing data that is not essential increases the volume of audit logs, potentially impacting database performance and increasing storage needs.
    *   **Increased Storage Costs for Audit Logs (Low Severity):** Storing unnecessary audit data leads to increased storage consumption and associated financial costs.
*   **Impact:**
    *   **Performance Degradation due to Excessive Logging (Medium Impact):**  Improves performance by reducing the volume of audit logs to only necessary data points, leveraging PaperTrail's selective configuration.
    *   **Increased Storage Costs for Audit Logs (Medium Impact):**  Reduces storage expenses by minimizing the amount of audit data stored, achieved through PaperTrail's configuration options.
*   **Currently Implemented:** Partially implemented. Some models like `PasswordResetRequest` are intentionally not under PaperTrail.
*   **Missing Implementation:** Requires a systematic review of all models to determine the necessity of enabling PaperTrail. For models with PaperTrail enabled, a detailed attribute-level review is needed to ensure only truly essential attributes are being tracked using `only` or `skip` options. A documented policy outlining which data requires auditing and why is currently absent.

