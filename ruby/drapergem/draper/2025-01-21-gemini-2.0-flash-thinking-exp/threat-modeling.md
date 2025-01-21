# Threat Model Analysis for drapergem/draper

## Threat: [Sensitive Data Exposure via Unfiltered Model Attributes](./threats/sensitive_data_exposure_via_unfiltered_model_attributes.md)

**Description:** An attacker could potentially gain access to sensitive data that is part of the underlying model but is unintentionally exposed through a decorator. This happens when a decorator directly accesses and renders model attributes that should be kept private or filtered based on user roles or context. The attacker might observe this data in the rendered HTML or API response.

**Impact:** Confidentiality breach, unauthorized access to personal or business-critical information, potential legal and reputational damage.

**Affected Draper Component:** Decorator classes, specifically methods accessing model attributes (e.g., `model.sensitive_attribute`).

**Risk Severity:** High

**Mitigation Strategies:**
*   **Principle of Least Privilege:** Only expose necessary data within decorators. Avoid directly accessing and rendering all model attributes.
*   **Explicit Attribute Whitelisting:** Define specific methods within decorators to access and format only the attributes intended for display.
*   **Authorization Checks within Decorators (with caution):**  While generally handled at the controller level, for complex presentation logic, consider carefully implementing authorization checks within decorators to filter data based on user permissions. Be cautious not to duplicate or contradict controller-level authorization.
*   **Code Reviews:** Regularly review decorator code to identify instances where sensitive data might be unintentionally exposed.

## Threat: [Cross-Site Scripting (XSS) through Unescaped Decorator Output](./threats/cross-site_scripting__xss__through_unescaped_decorator_output.md)

**Description:** An attacker could inject malicious client-side scripts into the application if a decorator renders user-provided data without proper HTML escaping. This could occur if a decorator directly outputs data received from user input (e.g., through the model) without sanitizing or escaping it. When a user views the page, the malicious script executes in their browser.

**Impact:** Account takeover, session hijacking, redirection to malicious websites, defacement of the website, and other client-side attacks.

**Affected Draper Component:** Decorator classes, specifically methods generating HTML output that includes potentially untrusted data.

**Risk Severity:** Critical

**Mitigation Strategies:**
*   **Automatic Escaping:** Utilize templating engines (like ERB or Haml) with automatic HTML escaping enabled when rendering data within decorators.
*   **Explicit Escaping:** When directly constructing HTML within decorators, use explicit escaping methods provided by your framework (e.g., `ERB::Util.html_escape` in Rails).
*   **Content Security Policy (CSP):** Implement a strong CSP to mitigate the impact of XSS attacks, even if some escaping is missed.
*   **Input Sanitization (with caution):** While primarily a concern at the model or controller level, be mindful of data already present in the model that might need sanitization before display in the decorator. However, focus on output escaping in decorators.

## Threat: [Authorization Bypass due to Decorator-Level Data Access without Context](./threats/authorization_bypass_due_to_decorator-level_data_access_without_context.md)

**Description:** If authorization checks are primarily performed at the controller level, and decorators directly access and display data without considering the current user's permissions, it might be possible to bypass these checks. An attacker might craft requests or manipulate data in a way that allows them to view information they shouldn't have access to, even if the controller initially authorized the request.

**Impact:** Unauthorized access to sensitive data, potential for privilege escalation, and data breaches.

**Affected Draper Component:** Decorator classes accessing model data without considering the current user's context.

**Risk Severity:** High

**Mitigation Strategies:**
*   **Pass User Context to Decorators:** When necessary, pass the current user object or relevant authorization information to decorators so they can make informed decisions about what data to display.
*   **Avoid Security-Sensitive Logic in Decorators (Generally):**  Ideally, authorization logic should be handled at the controller or service layer. Decorators should primarily focus on presentation.
*   **Consistent Authorization Enforcement:** Ensure that authorization checks are consistently applied across all layers of the application, including the presentation layer if decorators are involved in data filtering.

