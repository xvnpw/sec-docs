# Mitigation Strategies Analysis for paper-trail-gem/paper_trail

## Mitigation Strategy: [Selective Versioning](./mitigation_strategies/selective_versioning.md)

**1. Mitigation Strategy: Selective Versioning**

*   **Description:**
    1.  **Review Models:** Examine each model that uses `has_paper_trail`.
    2.  **Identify Sensitive Attributes:** Identify any attributes that contain sensitive data (passwords, API keys, PII, etc.).
    3.  **Use `only` or `except`:**
        *   If you only need to track a few attributes, use the `only` option within the `has_paper_trail` call: `has_paper_trail only: [:attribute1, :attribute2]`
        *   If you need to track most attributes but exclude a few, use the `except` option within the `has_paper_trail` call: `has_paper_trail except: [:sensitive_attribute1, :sensitive_attribute2]`
    4.  **Use `if` or `unless` (Conditional Versioning):**
        *   If versioning should only occur under certain conditions, use `if` or `unless` within the `has_paper_trail` call: `has_paper_trail if: :should_version?` (where `should_version?` is a method that returns true or false).  This method should be defined within the model.
    5.  **Test Thoroughly:** After making changes, thoroughly test to ensure that only the intended attributes are being tracked and that versioning occurs only when expected.  This testing should be part of your regular test suite.

*   **Threats Mitigated:**
    *   **Information Disclosure (Medium to High Severity):** Reduces the risk of exposing sensitive data stored in the `versions` table by limiting what is tracked.  The severity depends on the sensitivity of the data being potentially exposed.

*   **Impact:**
    *   **Information Disclosure:** Significantly reduces the risk, especially if sensitive attributes are explicitly excluded using `except`.  The impact is directly proportional to the effectiveness of your attribute selection.

*   **Currently Implemented:**
    *   Partially implemented. Some models use the `except` option to exclude certain attributes, but a comprehensive review of all models is needed. Found in model definitions (e.g., `app/models/user.rb`).

*   **Missing Implementation:**
    *   A systematic review of all models using `has_paper_trail` is needed to ensure that all sensitive attributes are appropriately excluded using `except` or `only`.
    *   Consideration should be given to using the `if` or `unless` options for more granular control over versioning, implementing the necessary conditional methods within the models.

## Mitigation Strategy: [Version Limit (per Record)](./mitigation_strategies/version_limit__per_record_.md)

**2. Mitigation Strategy: Version Limit (per Record)**

*   **Description:**
    1.  **Assess Needs:** Determine a reasonable limit for the number of versions to store *per record*.  Consider the typical lifecycle of your data, how often it changes, and the business need for historical data.  There's no one-size-fits-all answer; it depends on your application.
    2.  **Apply `:limit` Option:** In your model definitions, use the `:limit` option within the `has_paper_trail` call: `has_paper_trail limit: 100` (where 100 is the chosen limit – replace with your determined value).
    3.  **Test:** Thoroughly test the application to ensure that the version limit is enforced correctly.  Verify that older versions are automatically removed when the limit is reached.  This should be part of your automated test suite.

*   **Threats Mitigated:**
    *   **Denial of Service (DoS) (Medium Severity):** Prevents the `versions` table from growing indefinitely for any single record, mitigating the risk of excessive storage consumption and performance degradation caused by a single record being updated excessively.

*   **Impact:**
    *   **Denial of Service (DoS):** Provides a good level of protection against DoS attacks that attempt to create an excessive number of versions for a *single* record.  It doesn't protect against many records being updated a moderate number of times.

*   **Currently Implemented:**
    *   Not implemented.

*   **Missing Implementation:**
    *   This entire mitigation strategy is missing.  It requires determining an appropriate version limit for each model and applying the `:limit` option in the model definition (e.g., `app/models/product.rb`).

## Mitigation Strategy: [Thorough Testing of PaperTrail Configuration](./mitigation_strategies/thorough_testing_of_papertrail_configuration.md)

**3. Mitigation Strategy: Thorough Testing of PaperTrail Configuration**

*   **Description:**
    1.  **Create Test Suite:** Develop a dedicated test suite specifically for PaperTrail functionality *within your existing testing framework*.
    2.  **Test Version Creation:** Include tests that create, update, and delete records, verifying that versions are created as expected by `paper_trail`.
    3.  **Test Attribute Tracking:** Verify that only the intended attributes are being tracked, specifically testing the use of `only` and `except` options.  Assert against the contents of the `object` and `object_changes` columns.
    4.  **Test Conditional Versioning:** If using `if` or `unless`, test the conditions to ensure versions are created only when appropriate.  This involves calling the methods used in the `if` or `unless` conditions and verifying the version creation behavior.
    5.  **Test Version Limit:** If using `:limit`, test that the limit is enforced.  Create more versions than the limit and verify that the oldest versions are removed.
    6.  **Test Metadata:** Verify that metadata is being stored correctly using the `meta` option, if used.
    7.  **Test Associations:** If using PaperTrail with associations (and versioning those associations), test that versions are created correctly for associated records.
    8.  **Run Tests Regularly:** Integrate these tests into your continuous integration/continuous deployment (CI/CD) pipeline to run them automatically with every code change.  This ensures that any changes to the `paper_trail` configuration or related code don't introduce regressions.

*   **Threats Mitigated:**
    *   **Improper Configuration (Medium Severity):** Ensures that PaperTrail is configured correctly and behaves as expected, reducing the risk of unintended behavior due to misconfiguration.
    *   **Information Disclosure (Medium to High Severity):** Helps prevent accidental tracking of sensitive data by verifying the `only` and `except` configurations.
    *   **Denial of Service (DoS) (Low Severity):** Can help identify issues that might lead to excessive version creation (e.g., missing `:limit` or incorrect `if`/`unless` conditions).

*   **Impact:**
    *   **Improper Configuration:** Significantly reduces the risk of configuration errors.
    *   **Information Disclosure:** Reduces the risk by ensuring that only intended data is tracked.
    *   **Denial of Service (DoS):** Can help identify potential DoS vulnerabilities early in the development process.

*   **Currently Implemented:**
    *   Partially implemented. Some basic tests exist, but they are not comprehensive and do not cover all aspects of PaperTrail configuration. Found in the test suite (e.g., `spec/models/`).

*   **Missing Implementation:**
    *   A dedicated, comprehensive test suite for PaperTrail is needed, covering all configuration options and scenarios (especially `only`, `except`, `if`, `unless`, and `:limit`).
    *   Tests need to be integrated into the CI/CD pipeline to ensure they are run automatically.

## Mitigation Strategy: [Metadata Management](./mitigation_strategies/metadata_management.md)

**4. Mitigation Strategy: Metadata Management**

* **Description:**
    1. **Review Metadata Usage:** Carefully examine how you are using the `meta` option in `paper_trail`.
    2. **Avoid Sensitive Data:** *Never* store sensitive information directly in the metadata (e.g., user names, email addresses, IP addresses).
    3. **Use Identifiers:** If you need to associate versions with users or other entities, use identifiers (e.g., user IDs) rather than storing PII directly.
    4. **Controlled Access:** Ensure that access to the metadata is controlled through your application's authorization mechanisms.
    5. **Test:** Include tests that verify the correct and secure handling of metadata.

* **Threats Mitigated:**
    * **Information Disclosure (Medium Severity):** Prevents the exposure of sensitive information that might be inadvertently stored in the `meta` field.

* **Impact:**
    * **Information Disclosure:** Reduces the risk of exposing sensitive data if the `meta` option is used improperly.

* **Currently Implemented:**
    * Partially Implemented. User IDs are used, but a review is needed to ensure no other sensitive data is being stored. Found where `paper_trail` is configured and where `whodunnit` is set.

* **Missing Implementation:**
    * A thorough review of all uses of the `meta` option is needed to ensure compliance with this strategy.
    * Tests should be added to specifically verify the contents of the `meta` field.

