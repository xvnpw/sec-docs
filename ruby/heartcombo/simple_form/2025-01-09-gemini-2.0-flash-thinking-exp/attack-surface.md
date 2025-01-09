# Attack Surface Analysis for heartcombo/simple_form

## Attack Surface: [Cross-Site Scripting (XSS) via Unsafe Rendering of User-Provided Data](./attack_surfaces/cross-site_scripting__xss__via_unsafe_rendering_of_user-provided_data.md)

*   **Description:** Attackers can inject malicious scripts into web pages viewed by other users.
    *   **How simple_form Contributes:** If developers directly use unsanitized user-provided data (e.g., from a database) within `simple_form`'s labels, hints, error messages, or custom wrappers without proper escaping, the gem will render this malicious script into the HTML.
    *   **Example:**
        ```ruby
        # In a controller or view, fetching data from the database
        @user_description = "<script>alert('XSS Vulnerability!');</script>"

        # In the view using simple_form
        <%= f.input :description, label: @user_description %>
        ```
        This will render the script tag directly into the HTML label.
    *   **Impact:** Can lead to account hijacking, session theft, redirection to malicious sites, and defacement.
    *   **Risk Severity:** Critical

## Attack Surface: [HTML Injection via Custom Input Wrappers or Components](./attack_surfaces/html_injection_via_custom_input_wrappers_or_components.md)

*   **Description:** Attackers can inject arbitrary HTML into the page structure.
    *   **How simple_form Contributes:** `simple_form`'s flexibility allows developers to create custom input wrappers and components. If these customizations don't properly escape dynamic content, attackers can inject malicious HTML.
    *   **Example:**
        ```ruby
        # Custom wrapper implementation (potentially vulnerable)
        SimpleForm.wrappers.basic_wrapper = proc do |b|
          b.use :html5
          b.use :placeholder
          b.optional :maxlength
          b.optional :pattern
          b.use :label, class: 'form-label'
          b.wrapper tag: :div, class: 'input-group' do |ba|
            ba.use :input, class: 'form-control', **wrapper_options  # Potentially unsafe
          end
          b.use :hint,  wrap_with: { tag: :small, class: 'form-text text-muted' }
          b.use :error, wrap_with: { tag: :div, class: 'invalid-feedback' }
        end
        ```
        If `wrapper_options` contains unescaped user input, it can lead to HTML injection.
    *   **Impact:** Can be used for phishing attacks, defacement, or tricking users into performing unintended actions.
    *   **Risk Severity:** High

