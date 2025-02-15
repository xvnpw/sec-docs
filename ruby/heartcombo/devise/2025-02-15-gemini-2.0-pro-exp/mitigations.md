# Mitigation Strategies Analysis for heartcombo/devise

## Mitigation Strategy: [Enable Devise's Paranoid Mode](./mitigation_strategies/enable_devise's_paranoid_mode.md)

*   **Description:**
    1.  Open the Devise initializer file: `config/initializers/devise.rb`.
    2.  Locate the line `config.paranoid = ...`.
    3.  Ensure it's set to `true`: `config.paranoid = true`.
    4.  Restart your Rails server.
    5.  Test password reset with valid/invalid emails to confirm identical response times.

*   **Threats Mitigated:**
    *   **Account Enumeration (Timing Attack on Password Reset):** High Severity. Attackers identify registered emails via timing differences.
    *   **Account Enumeration (Error Messages - Password Reset):** Medium Severity.  Specific error messages reveal registered emails.

*   **Impact:**
    *   **Account Enumeration (Timing Attack):** Risk reduced from High to Low.
    *   **Account Enumeration (Error Messages):** Risk reduced from Medium to Low (with generic error messages).

*   **Currently Implemented:**  Yes/No (Specify: e.g., "Yes, in `config/initializers/devise.rb`")

*   **Missing Implementation:**  (Specify: e.g., "None" or "Need to verify in production")

## Mitigation Strategy: [Use Generic Error Messages (Within Devise Views/Controllers)](./mitigation_strategies/use_generic_error_messages__within_devise_viewscontrollers_.md)

*   **Description:**
    1.  Generate Devise views: `rails generate devise:views`.
    2.  Review these views (and any custom Devise controllers):
        *   `app/views/devise/sessions/new.html.erb`
        *   `app/views/devise/passwords/new.html.erb`
        *   `app/views/devise/passwords/edit.html.erb`
        *   `app/views/devise/registrations/new.html.erb`
    3.  Replace specific error messages (e.g., "Email not found") with generic ones (e.g., "Invalid email or password"). Use `flash[:alert]`.
    4.  Review custom controllers inheriting from Devise for similar issues.
    5.  Test all authentication flows.

*   **Threats Mitigated:**
    *   **Account Enumeration (Error Messages - Login):** Medium Severity. Specific messages reveal existing accounts.
    *   **Account Enumeration (Error Messages - Password Reset):** Medium Severity.
    *   **Information Disclosure:** Low Severity.

*   **Impact:**
    *   **Account Enumeration (Login/Password Reset):** Risk reduced from Medium to Low.
    *   **Information Disclosure:** Risk reduced from Low to Negligible.

*   **Currently Implemented:** Yes/No (Specify: e.g., "Partially, views updated, need to check controllers")

*   **Missing Implementation:** (Specify: e.g., "Custom controller `Users::CustomAuthController`")

## Mitigation Strategy: [Implement Devise's Lockable Module](./mitigation_strategies/implement_devise's_lockable_module.md)

*   **Description:**
    1.  Add `:lockable` to your Devise model (e.g., `app/models/user.rb`):
        ```ruby
        devise :database_authenticatable, :registerable,
               :recoverable, :rememberable, :validatable, :lockable
        ```
    2.  Run migrations if needed.
    3.  Configure in `config/initializers/devise.rb`:
        ```ruby
        config.lock_strategy = :failed_attempts
        config.maximum_attempts = 5
        config.unlock_strategy = :time
        config.unlock_in = 1.hour
        ```
    4.  Test by entering incorrect passwords.
    5.  If using `:email` unlock, ensure email configuration is correct.

*   **Threats Mitigated:**
    *   **Brute-Force Attacks (Login):** High Severity.
    *   **Credential Stuffing:** High Severity.

*   **Impact:**
    *   **Brute-Force Attacks:** Risk reduced from High to Low.
    *   **Credential Stuffing:** Risk reduced from High to Low.

*   **Currently Implemented:** Yes/No (Specify: e.g., "Yes, with defaults in `devise.rb` and `user.rb`")

*   **Missing Implementation:** (Specify: e.g., "Configure email notifications for unlocks")

## Mitigation Strategy: [Regenerate Session ID on Login (Verify Devise Default)](./mitigation_strategies/regenerate_session_id_on_login__verify_devise_default_.md)

*   **Description:**
    1.  This is Devise's *default* behavior. No explicit configuration is usually needed.
    2.  **Crucially:** Review your code (especially custom authentication) to ensure you are *not* manually setting the session ID *before* Devise's authentication. Avoid `session[:user_id] = user.id` prematurely.
    3.  Test by logging in and checking the session cookie before/after.

*   **Threats Mitigated:**
    *   **Session Fixation:** High Severity.

*   **Impact:**
    *   **Session Fixation:** Risk reduced from High to Low (assuming no interference).

*   **Currently Implemented:** Yes/No (Specify: e.g., "Yes, using Devise default. Code reviewed.")

*   **Missing Implementation:** (Specify: e.g., "None, assuming default behavior")

## Mitigation Strategy: [Use Strong Parameters (Within Devise Controllers)](./mitigation_strategies/use_strong_parameters__within_devise_controllers_.md)

*   **Description:**
    1.  For custom controllers inheriting from Devise (e.g., `Users::RegistrationsController`), define `configure_permitted_parameters`.
    2.  Use `devise_parameter_sanitizer.permit` to whitelist allowed attributes for `sign_up` and `account_update`:
        ```ruby
        class Users::RegistrationsController < Devise::RegistrationsController
          before_action :configure_permitted_parameters

          protected

          def configure_permitted_parameters
            devise_parameter_sanitizer.permit(:sign_up, keys: [:email, :password, :password_confirmation, :username])
            devise_parameter_sanitizer.permit(:account_update, keys: [:email, :password, :password_confirmation, :current_password, :username])
          end
        end
        ```
    3.  **Crucially:** Only include user-modifiable attributes. Exclude `admin`, `role`, etc.
    4.  If *not* using custom controllers, Devise's default sanitization is usually safe, but explicit is better.
    5.  Test by submitting requests with unexpected parameters.

*   **Threats Mitigated:**
    *   **Mass Assignment:** High Severity.

*   **Impact:**
    *   **Mass Assignment:** Risk reduced from High to Low.

*   **Currently Implemented:** Yes/No (Specify: e.g., "Yes, in `Users::RegistrationsController`")

*   **Missing Implementation:** (Specify: e.g., "`Users::ProfilesController`")

## Mitigation Strategy: [Manage "Remember Me" Token Duration (Devise Setting)](./mitigation_strategies/manage_remember_me_token_duration__devise_setting_.md)

*   **Description:**
    1.  Open `config/initializers/devise.rb`.
    2.  Set `config.remember_for` to a reasonable duration:
        ```ruby
        config.remember_for = 2.weeks # Or shorter
        ```
    3.  Test the "remember me" functionality.

*   **Threats Mitigated:**
    *   **Replay Attacks (Remember Me Token):** Medium Severity.

*   **Impact:**
    *   **Replay Attacks:** Risk reduced from Medium to Low (depending on duration).

*   **Currently Implemented:** Yes/No (Specify: e.g., "Yes, 1 week in `devise.rb`")

*   **Missing Implementation:** (Specify: e.g., "None")

## Mitigation Strategy: [Enforce Email Confirmation (Devise Confirmable Module)](./mitigation_strategies/enforce_email_confirmation__devise_confirmable_module_.md)

*   **Description:**
    1.  Add `:confirmable` to your Devise model (e.g., `app/models/user.rb`).
    2.  Run migrations.
    3.  Ensure email configuration is correct.
    4.  Use `before_action :authenticate_user!` to protect routes. Devise blocks unconfirmed users.
    5.  **Crucially:** Do *not* override Devise's confirmation to allow unconfirmed access.
    6.  Test by creating an account and trying to access protected resources *before* confirmation.

*   **Threats Mitigated:**
    *   **Unconfirmed Account Access:** Medium Severity.
    *   **Spam/Abuse:** Medium Severity.

*   **Impact:**
    *   **Unconfirmed Account Access:** Risk reduced from Medium to Low.
    *   **Spam/Abuse:** Risk reduced from Medium to Low.

*   **Currently Implemented:** Yes/No (Specify: e.g., "Yes, in User model, enforced with `authenticate_user!`")

*   **Missing Implementation:** (Specify: e.g., "None")

## Mitigation Strategy: [Validate Redirect URLs (Within Devise Overrides)](./mitigation_strategies/validate_redirect_urls__within_devise_overrides_.md)

*   **Description:**
    1.  If overriding Devise's redirects (e.g., `after_sign_out_path_for`, `after_confirmation_path_for`), validate the URL.
    2.  **Best:** Use a whitelist:
        ```ruby
        def after_sign_out_path_for(resource_or_scope)
          allowed_paths = ['/', '/about']
          return root_path unless params[:redirect_to].in?(allowed_paths)
          params[:redirect_to]
        end
        ```
    3.  **Alternative (Less Secure):** Robust URL validation. *Never* use user input directly without validation.
    4.  Test with malicious redirect URLs.

*   **Threats Mitigated:**
    *   **Open Redirect:** Medium Severity.

*   **Impact:**
    *   **Open Redirect:** Risk reduced from Medium to Low (with validation).

*   **Currently Implemented:** Yes/No (Specify: e.g., "Partially, domain check. Need whitelist.")

*   **Missing Implementation:** (Specify: e.g., "`after_confirmation_path_for` needs review")

