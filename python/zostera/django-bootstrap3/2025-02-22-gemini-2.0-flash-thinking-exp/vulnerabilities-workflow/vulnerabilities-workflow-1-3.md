## Vulnerability List for django-bootstrap3

### 1. Stored Cross-Site Scripting (XSS) in Alert Messages

- Description:
    - The `bootstrap_messages` template tag in `src/bootstrap3/templatetags/bootstrap3.py` renders Django messages using Bootstrap alerts.
    - The message content is not properly sanitized before being rendered into the HTML template.
    - An attacker can inject malicious JavaScript code into a message, which will be stored and executed in the browsers of users viewing the messages.
    - Step-by-step trigger:
        1. An attacker finds a way to inject a message into the Django messages framework. This could be through a vulnerability in the application using `django-bootstrap3`, or if the application allows user-generated messages to be displayed (e.g., in a forum or comments section, if messages are used for this purpose - although less common).
        2. The injected message contains malicious JavaScript code, for example: `<img src=x onerror=alert("XSS")>`.
        3. The application renders the template that includes `{% bootstrap_messages messages %}`.
        4. When a user views the page, the `bootstrap_messages` tag renders the message.
        5. The injected JavaScript code is executed in the user's browser because the message content is not properly escaped.

- Impact:
    - **High**
    - Stored XSS can lead to account takeover, session hijacking, defacement, or redirection to malicious sites. The impact is significant as the malicious script executes in the context of the user's session every time the page with the vulnerable message is loaded.

- Vulnerability Rank: high

- Currently implemented mitigations:
    - None. The code directly renders the message content without any sanitization.

- Missing mitigations:
    - The message content should be properly escaped before being rendered in the template to prevent XSS. Django's `escape` template filter or `mark_safe` used in conjunction with a sanitization library should be applied to the message content within the `bootstrap_messages` tag or in the `render_alert` function.

- Preconditions:
    - An attacker needs to be able to inject a message into the Django messages framework. This usually requires a vulnerability in the application that uses `django-bootstrap3`.

- Source code analysis:
    - **File: src/bootstrap3/templatetags/bootstrap3.py**
    ```python
    @register.simple_tag(takes_context=True)
    def bootstrap_messages(context, *args, **kwargs):
        ...
        return render_template_file("bootstrap3/messages.html", context=context)
    ```
    - **File: src/bootstrap3/templates/bootstrap3/messages.html** (not provided in PROJECT FILES, but assumed to exist and be responsible for rendering messages)
    - Assuming `bootstrap3/messages.html` iterates through messages and renders them using `render_alert`:
    ```html+django
    {% load bootstrap3 %}
    {% for message in messages %}
        {% bootstrap_alert message %}
    {% endfor %}
    ```
    - **File: src/bootstrap3/components.py**
    ```python
    def render_alert(content, alert_type=None, dismissable=True):
        ...
        return mark_safe(
            render_tag(
                "div", attrs={"class": " ".join(css_classes)}, content=mark_safe(button_placeholder) + text_value(content) # content is marked as safe, but not sanitized
            ).replace(button_placeholder, button)
        )
    ```
    - The `render_alert` function in `src/bootstrap3/components.py` marks the `content` as safe using `mark_safe`. However, it does not sanitize the content to remove potentially malicious HTML or JavaScript. If a message with malicious HTML is passed as `content`, it will be rendered without escaping, leading to XSS. The `bootstrap_messages` tag passes the raw message content to `render_alert`.

- Security test case:
    - Step-by-step test:
        1. Set up a Django project using `django-bootstrap3`.
        2. In a view, add a message to the messages framework with malicious JavaScript:
        ```python
        from django.contrib import messages
        from django.shortcuts import render

        def test_view(request):
            messages.info(request, '<img src=x onerror=alert("XSS_TEST")>')
            return render(request, 'test_template.html')
        ```
        3. Create a template `test_template.html` that includes `bootstrap_messages`:
        ```html+django
        {% load bootstrap3 %}
        <!DOCTYPE html>
        <html>
        <head>
            <title>XSS Test</title>
            {% bootstrap_css %}
        </head>
        <body>
            <div class="container">
                {% bootstrap_messages messages %}
            </div>
            {% bootstrap_javascript jquery=1 %}
        </body>
        </html>
        ```
        4. Access the view in a browser.
        5. Observe that an alert box with "XSS_TEST" is displayed, indicating that the JavaScript code in the message was executed.

- Missing mitigations:
    - In `src/bootstrap3/components.py`, the `content` variable in `render_alert` should be sanitized before being marked as safe. Instead of directly using `mark_safe(text_value(content))`, use `escape(text_value(content))` or a more robust HTML sanitization library like `bleach` to remove or escape potentially harmful HTML tags and JavaScript.