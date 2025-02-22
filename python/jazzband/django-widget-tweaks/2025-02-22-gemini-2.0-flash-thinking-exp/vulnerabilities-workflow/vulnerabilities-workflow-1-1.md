### Vulnerability List

- Vulnerability Name: Cross-Site Scripting (XSS) in widget attribute manipulation
- Description:
    The `django-widget-tweaks` library allows setting arbitrary HTML attributes on form fields using template tags and filters such as `attr` and the `render_field` tag. It does not properly sanitize or escape attribute values when these values are dynamically set using template variables or filter arguments. This lack of sanitization allows for the injection of malicious JavaScript code into HTML attributes, such as `onclick`, `onmouseover`, etc. An attacker can exploit this by crafting input that, when rendered by a Django template using `django-widget-tweaks`, injects JavaScript code into the HTML. When a user interacts with the form field (e.g., clicks or hovers), the injected JavaScript code will be executed in their browser, leading to Cross-Site Scripting (XSS).

    Steps to trigger the vulnerability:
    1. An attacker crafts a malicious string containing JavaScript code intended to be used as an HTML attribute value. For example: `" onclick='alert(\"XSS\")'"` or `" onmouseover='alert(\"XSS\")' "`.
    2. The attacker finds a way to inject this malicious string into a Django template context variable that is used with `django-widget-tweaks` template tags or filters to set HTML attributes. Alternatively, the attacker might be able to directly influence the arguments passed to the `attr` filter or `render_field` tag within a template if user input is somehow incorporated there.
    3. The Django template, using `django-widget-tweaks`, renders a form field and applies the attribute modification using the malicious string as the attribute value. For example, using `{% render_field form.field attr='attribute_name:"' + malicious_string + '"' %}` or `{{ form.field|attr:'attribute_name:"' + malicious_string + '"' }}`.
    4. The rendered HTML form field will now contain the injected JavaScript code within the specified HTML attribute.
    5. When a user views the page and interacts with the form field in a way that triggers the injected attribute (e.g., clicking if `onclick` was injected, hovering if `onmouseover`), the JavaScript code executes in the user's browser.

- Impact:
    Cross-site scripting (XSS). Successful exploitation allows an attacker to execute arbitrary JavaScript code in the context of a user's browser session when they interact with the form field. This can lead to various malicious activities, including:
    - Account hijacking: Stealing session cookies or other authentication tokens to impersonate the user.
    - Data theft: Accessing sensitive information displayed on the page or making requests on behalf of the user to exfiltrate data.
    - Defacement: Modifying the content of the web page visible to the user.
    - Redirection: Redirecting the user to a malicious website.
    - Further attacks: Using the XSS vulnerability as a stepping stone for more complex attacks against the user or the application.

- Vulnerability Rank: high

- Currently implemented mitigations:
    None. The `django-widget-tweaks` library does not perform any HTML escaping or sanitization of attribute values that are set using its template tags and filters. It relies on Django's default template rendering, which, in this context, is insufficient to prevent XSS in HTML attributes when values are dynamically injected.

- Missing mitigations:
    The library must implement HTML escaping for attribute values before they are injected into the HTML output. Specifically:
    - In the `set_attr` filter, `append_attr` filter, and within the `render_field` tag's attribute processing logic in `widget_tweaks/templatetags/widget_tweaks.py`, any value that is intended to be set as an HTML attribute value should be passed through Django's HTML escaping function (e.g., `django.utils.html.escape`). This will ensure that any potentially malicious JavaScript code within the attribute value is rendered harmless by converting special characters (like `<`, `>`, `"`, `'`) into their HTML entity equivalents.

- Preconditions:
    1. A Django application is using the `django-widget-tweaks` library version which is vulnerable.
    2. The application uses `django-widget-tweaks` template tags or filters (`attr`, `render_field`, etc.) to dynamically set HTML attributes of form fields.
    3. There is a scenario where an attacker can control or influence the values of template context variables that are used as attribute values via `django-widget-tweaks`, or directly control the arguments to `attr` filter or `render_field` tag in templates where user input is processed. Even in cases where templates are not directly user-controlled, if user-provided data is rendered into a form and attributes are manipulated by widget-tweaks without proper escaping of this user data, XSS is possible.

- Source code analysis:
    1. File: `/code/widget_tweaks/templatetags/widget_tweaks.py`
    2. Function: `_process_field_attributes(field, attr, process)`: This function is central to how attributes are processed. It parses the attribute name and value from the `attr` string.
    ```python
    def _process_field_attributes(field, attr, process):
        params = re.split(r"(?<!:):(?!:)", attr, 1)
        attribute = params[0].replace("::", ":")
        value = params[1] if len(params) == 2 else True
        field = copy(field)
        old_as_widget = field.as_widget

        def as_widget(self, widget=None, attrs=None, only_initial=False):
            attrs = attrs or {}
            process(widget or self.field.widget, attrs, attribute, value) # Vulnerable line - value is not escaped
            if attribute == "type":
                self.field.widget.input_type = value
                del attrs["type"]
            html = old_as_widget(widget, attrs, only_initial)
            self.as_widget = old_as_widget
            return html

        field.as_widget = types.MethodType(as_widget, field)
        return field
    ```
    In the `as_widget` inner function, the `process` function (which is either from `set_attr` or `append_attr`) directly sets or appends the `value` to the `attrs` dictionary: `attrs[attribute] = value` or `attrs[attribute] += " " + value`.  Critically, the `value` variable, which originates from user-provided template input or filter arguments, is not HTML escaped before being placed into the `attrs` dictionary. This dictionary is then used by Django's form rendering mechanism to generate HTML attributes. Django's default template escaping mechanisms do not seem to apply to attribute values in this scenario when attributes are set this way, leading to the XSS vulnerability.

    3. Function: `set_attr(field, attr)` and `append_attr(field, attr)`: These filters use `_process_field_attributes` and their `process` functions directly assign attribute values without escaping.
    ```python
    def set_attr(field, attr):
        def process(widget, attrs, attribute, value):
            attrs[attribute] = value # Vulnerable line - value is not escaped
        return _process_field_attributes(field, attr, process)

    def append_attr(field, attr):
        def process(widget, attrs, attribute, value):
            if attrs.get(attribute):
                attrs[attribute] += " " + value # Vulnerable line - value is not escaped
            elif widget.attrs.get(attribute):
                attrs[attribute] = widget.attrs[attribute] + " " + value # Vulnerable line - value is not escaped
            else:
                attrs[attribute] = value # Vulnerable line - value is not escaped
        return _process_field_attributes(field, attr, process)
    ```
    4. Tag: `render_field(parser, token)`: This tag also uses `set_attr` and `append_attr` filters to apply attributes. The values in the tag can come from template variables, which if attacker-controlled, can lead to XSS.

- Security test case:
    1. Set up a Django project with `django-widget-tweaks` installed.
    2. Create a Django app and define a simple form in `forms.py`:
    ```python
    from django import forms

    class TestForm(forms.Form):
        name = forms.CharField()
    ```
    3. Create a Django view in `views.py`:
    ```python
    from django.shortcuts import render
    from .forms import TestForm

    def test_xss_view(request):
        form = TestForm()
        malicious_attribute_value = ' onclick="alert(\'XSS\')"'
        context = {'form': form, 'xss_attr_value': malicious_attribute_value}
        return render(request, 'test_xss.html', context)
    ```
    4. Create a Django template `test_xss.html` in your templates directory:
    ```html
    {% load widget_tweaks %}
    <!DOCTYPE html>
    <html>
    <head>
        <title>XSS Test</title>
    </head>
    <body>
        <form method="post">
            {% csrf_token %}
            {% render_field form.name attr='id:"name-field"' attr='class:"form-control"' attr='type:"text"' attr='name:"user_name"' attr='value:"test value"' attr='placeholder:"Enter your name"' attr='onclick:"alert(\'XSS\')"' %}
            <button type="submit">Submit</button>
        </form>
    </body>
    </html>
    ```
    5. Configure URLs in `urls.py` to access the view:
    ```python
    from django.urls import path
    from . import views

    urlpatterns = [
        path('xss_test/', views.test_xss_view, name='xss_test'),
    ]
    ```
    6. Run the Django development server.
    7. Access the URL `/xss_test/` in a web browser.
    8. Click on the input field.
    9. Observe that an alert box with "XSS" is displayed. This confirms that the JavaScript code injected via the `onclick` attribute was executed, demonstrating the XSS vulnerability.

This test case directly injects the `onclick` attribute with JavaScript using the `render_field` tag. A real-world scenario might involve injecting this value through user-controlled data into a template variable, which is then used in the `attr` filter or `render_field` tag.