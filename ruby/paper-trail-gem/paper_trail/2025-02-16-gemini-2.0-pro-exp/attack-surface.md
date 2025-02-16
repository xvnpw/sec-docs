# Attack Surface Analysis for paper-trail-gem/paper_trail

## Attack Surface: [Unauthorized Version Record Modification](./attack_surfaces/unauthorized_version_record_modification.md)

*   **Description:** Direct manipulation of the `versions` table (or the table `paper_trail` is configured to use) to alter or delete historical data, bypassing `paper_trail`'s intended controls.
*   **How `paper_trail` Contributes:** `paper_trail` *creates and manages* the `versions` table, making it the direct target for data integrity attacks related to version history. This is its core function.
*   **Example:** An attacker with database access uses a SQL `UPDATE` statement to change the `object` column of a version record, altering the recorded state of a financial transaction to show a lower amount.
*   **Impact:** Loss of audit trail integrity, potential for fraudulent activity, legal and compliance violations, reputational damage.
*   **Risk Severity:** Critical
*   **Mitigation Strategies:**
    *   **Database-Level Permissions (Primary):** The application's database user *must* have only `INSERT` (and optionally `SELECT`) privileges on the `versions` table.  Absolutely *no* `UPDATE` or `DELETE` privileges. This is the most crucial defense, directly protecting the data `paper_trail` manages.
    *   **Application-Level Access Control:** Ensure *no* code paths allow direct modification of the `versions` table outside of `paper_trail`'s controlled methods. Avoid any custom SQL queries or ActiveRecord manipulations that bypass `paper_trail`. This prevents circumvention of `paper_trail`'s mechanisms.
    *   **Regular Database Audits:** Implement periodic audits of the `versions` table, potentially using checksums or database auditing features, to detect unauthorized changes to the data `paper_trail` stores.

## Attack Surface: [`whodunnit` Spoofing](./attack_surfaces/_whodunnit__spoofing.md)

*   **Description:** An attacker manipulates the `whodunnit` field, a core component of `paper_trail`'s audit trail, to falsely attribute actions to another user or system process.
*   **How `paper_trail` Contributes:** `paper_trail` *defines and uses* the `whodunnit` field to track the originator of changes. This is a fundamental part of `paper_trail`'s functionality.
*   **Example:** An attacker modifies a request to include a different user's ID in the data used to set `PaperTrail.request.whodunnit`, causing their malicious changes to be attributed to the innocent user within the `paper_trail` records.
*   **Impact:** Misattribution of actions within the audit trail, difficulty in identifying the true perpetrator, potential for framing innocent users.
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   **Secure Authentication:** Implement robust authentication to ensure the user's identity is reliably established. This provides the foundation for a trustworthy `whodunnit`.
    *   **Controller-Level `whodunnit` Setting:** Set `PaperTrail.request.whodunnit` in a `before_action` in your controllers, *immediately after* successful authentication, and *never* based on user-supplied input. This ensures `paper_trail` receives accurate attribution data. Example:
        ```ruby
        class ApplicationController < ActionController::Base
          before_action :set_paper_trail_whodunnit

          private

          def user_for_paper_trail
            user_signed_in? ? current_user.id : 'Public User' # Or a system user ID
          end
        end
        ```
    *   **Review Custom `whodunnit` Methods:** If you have a custom `user_for_paper_trail` method (a `paper_trail` specific feature), thoroughly audit it for vulnerabilities.

## Attack Surface: [Sensitive Data Exposure in Version History](./attack_surfaces/sensitive_data_exposure_in_version_history.md)

*   **Description:** Sensitive information (passwords, API keys, PII) is inadvertently stored in the `object` or `object_changes` columns of the `versions` table, *directly exposing data through paper_trail's core mechanism*.
*   **How `paper_trail` Contributes:** `paper_trail` *serializes model data*, including potentially sensitive attributes, into the `object` and `object_changes` columns of the `versions` table. This is how `paper_trail` stores its historical data.
*   **Example:** A user model includes a `password` attribute (which should be a hashed password, but for this example, assume it's plain text). `paper_trail`, by its design, stores the plain-text password in the `object` column when the user is created or updated.
*   **Impact:** Data breach, privacy violations, potential for further attacks (e.g., credential stuffing).
*   **Risk Severity:** Critical
*   **Mitigation Strategies:**
    *   **Attribute Filtering (Primary):** Use the `:ignore` option in `has_paper_trail` to *explicitly exclude* sensitive attributes from being tracked *by paper_trail*. This is a direct `paper_trail` configuration setting. Example:
        ```ruby
        class User < ApplicationRecord
          has_paper_trail ignore: [:password, :api_key, :credit_card_number]
        end
        ```
    *   **Data Sanitization/Encryption:** If sensitive data *must* be tracked, sanitize or encrypt it *before* it's stored by `paper_trail`. This requires custom serialization logic that interacts directly with how `paper_trail` handles data.
    *   **Restricted Access:** Limit access to the `versions` table (managed by `paper_trail`) and any UI that displays version history to authorized personnel only.

## Attack Surface: [Bypassing Versioning Controls](./attack_surfaces/bypassing_versioning_controls.md)

*   **Description:** An attacker finds a way to modify tracked models *without* triggering the creation of new versions, directly circumventing `paper_trail`'s intended functionality.
*   **How `paper_trail` Contributes:** This attack directly targets `paper_trail`'s core purpose: to track changes. The vulnerability lies in the ability to *avoid* `paper_trail`'s mechanisms.
*   **Example:** An attacker discovers a code path that uses direct SQL `UPDATE` statements on a tracked model, bypassing ActiveRecord callbacks and thus `paper_trail`'s hooks.
*   **Impact:** Data changes occur without being recorded, undermining the audit trail provided by `paper_trail`.
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   **Comprehensive Model Configuration:** Ensure all relevant models and attributes are correctly configured for versioning with `paper_trail`. Carefully review `:only`, `:ignore`, `:if`, and `:unless` conditions – all `paper_trail` specific settings.
    *   **Code Review:** Thoroughly review code for any direct SQL modifications or ActiveRecord manipulations that bypass `paper_trail`'s hooks.
    *   **Testing:** Include comprehensive tests (including negative tests) to verify that all expected actions trigger version creation by `paper_trail` and that attempts to bypass versioning fail.
    *   **`without_versioning` Audit:** Scrutinize the use of `without_versioning` (a `paper_trail` specific method). It should be used *extremely* rarely and only with strong justification and thorough review. This method directly disables `paper_trail`.

