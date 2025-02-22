## Combined Vulnerability List for django-countries Project

### 1. Potential Cross-Site Scripting (XSS) in Flag URL Generation via Misconfiguration

* Description:
    1. The `CountrySelectWidget` in `django_countries/widgets.py` generates JavaScript code in the `onchange` attribute of the select widget to dynamically update the flag image source when the selected country changes.
    2. This JavaScript code is constructed using string formatting with `%s` placeholder in `COUNTRY_CHANGE_HANDLER`.
    3. The `%s` placeholder is replaced with the result of `urlparse.urljoin(settings.STATIC_URL, settings.COUNTRIES_FLAG_URL)`.
    4. If a developer misconfigures `settings.COUNTRIES_FLAG_URL` to include single quotes or other JavaScript injection payloads, and does not properly sanitize it, this payload can be injected into the `onchange` attribute.
    5. When a user interacts with the `CountrySelectWidget` and triggers the `onchange` event, the injected JavaScript code will be executed in the user's browser, leading to XSS.

* Impact:
    * High
    * An attacker can inject arbitrary JavaScript code into the web page by exploiting a misconfigured `settings.COUNTRIES_FLAG_URL`.
    * This can lead to various malicious activities such as stealing user cookies, session hijacking, redirecting users to malicious websites, or defacing the website.

* Vulnerability Rank: High

* Currently implemented mitigations:
    * No direct mitigation in the project code to prevent misconfiguration of `settings.COUNTRIES_FLAG_URL`.
    * The project assumes that developers will configure `settings.COUNTRIES_FLAG_URL` with a safe URL.
    * Output of the widget itself and flag URLs are escaped using Django's escaping mechanisms to prevent XSS in the HTML rendering context, but not within the Javascript event handler itself.

* Missing mitigations:
    * Input validation or sanitization for `settings.COUNTRIES_FLAG_URL` to prevent injection of single quotes or JavaScript code.
    * Documentation explicitly warning developers about the security implications of misconfiguring `settings.COUNTRIES_FLAG_URL` and recommending safe configuration practices.

* Preconditions:
    * A developer must misconfigure `settings.COUNTRIES_FLAG_URL` in their Django project to include a JavaScript payload.
    * An attacker needs to find a page that uses `CountrySelectWidget` with the misconfigured settings.

* Source code analysis:
    1. File: `/code/django_countries/widgets.py`
    2. Look at `COUNTRY_CHANGE_HANDLER` definition:
    ```python
    COUNTRY_CHANGE_HANDLER = (
        "var e=document.getElementById('flag_' + this.id); "
        "if (e) e.src = '%s'"
        ".replace('{code}', this.value.toLowerCase() || '__')"
        ".replace('{code_upper}', this.value.toUpperCase() || '__');"
    )
    ```
    3. Look at `CountrySelectWidget.render` method:
    ```python
    def render(self, name, value, attrs=None, renderer=None):
        ...
        if widget_id:
            flag_id = f"flag_{widget_id}"
            attrs["onchange"] = COUNTRY_CHANGE_HANDLER % urlparse.urljoin(
                settings.STATIC_URL, settings.COUNTRIES_FLAG_URL
            )
        ...
    ```
    4. The `COUNTRY_CHANGE_HANDLER % urlparse.urljoin(...)` line formats the JavaScript string. If `settings.COUNTRIES_FLAG_URL` is set to something like `"flags/{code}.gif'; alert('XSS');//"`, then the generated `onchange` attribute will contain the alert.

* Security test case:
    1. In a Django project that uses `django-countries`, modify the `settings.py` file to set `COUNTRIES_FLAG_URL = "flags/{code}.gif';alert('XSS')//"` or `COUNTRIES_FLAG_URL = "flags/{code}.gif'</script><script>alert('XSS')</script><script>'"`
    2. Create a Django form that uses `CountryField` with `CountrySelectWidget`.
    3. Render this form in a template and access the page in a browser.
    4. Inspect the HTML source code of the rendered page. Find the `<select>` element for the country field.
    5. Check the `onchange` attribute of the `<select>` element. It should contain the injected JavaScript code from `COUNTRIES_FLAG_URL`. For example:
    ```html
    <select onchange="var e=document.getElementById('flag_' + this.id); if (e) e.src = '/static-assets/flags/{code}.gif\';alert(\'XSS\')//'.replace('{code}', this.value.toLowerCase() || '__').replace('{code_upper}', this.value.toUpperCase() || '__');" ...>
    ```
    6. Interact with the select dropdown on the page by changing the selected country.
    7. An XSS alert box (`alert('XSS')`) should appear in the browser, confirming the vulnerability.