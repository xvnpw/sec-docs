## Combined Vulnerability List

This document consolidates identified vulnerabilities from multiple reports into a single list, removing duplicates and providing detailed descriptions, impacts, mitigations, and testing procedures for each.

### Vulnerability: CSV Injection in Excel Renderers

- **Description:**
    - An attacker can inject malicious formulas into CSV data served by Django REST Pandas when using Excel renderers (PandasExcelRenderer, PandasOldExcelRenderer). When a user opens the exported Excel file, these injected formulas can be executed by Excel, potentially leading to arbitrary command execution.
    - **Step-by-step trigger:**
        1. An attacker identifies an API endpoint in a Django REST Pandas application that exports data in Excel format (e.g., `/api/data.xlsx`).
        2. The attacker crafts a request to this endpoint such that the data returned by the API, and subsequently included in the exported Excel file, contains a CSV injection payload. This could be achieved by manipulating input parameters that influence the data being processed by the API. For example, if the API endpoint displays data based on a search query, the attacker could include the payload in the search query. A common CSV injection payload for Excel is `=cmd|' /C calc'!A0` which attempts to execute the calculator application.
        3. The server processes the request and generates an Excel file containing the injected payload.
        4. The attacker tricks a user into downloading and opening the malicious Excel file.
        5. When the user opens the Excel file, Excel interprets the injected string as a formula and executes it. In the example payload `=cmd|' /C calc'!A0`, this would lead to the execution of the `calc` command, opening the calculator application on the user's system. More dangerous commands could also be injected.

- **Impact:**
    - Arbitrary command execution on the victim's machine when they open the exported Excel file.
    - Depending on the injected formula, this could lead to:
        - Information disclosure: attacker could potentially read local files or system information.
        - Data exfiltration: attacker could send sensitive data to an external server.
        - System compromise: in more advanced scenarios, attacker might be able to gain persistent access to the user's system.

- **Vulnerability Rank:** High

- **Currently implemented mitigations:**
    - None. The Django REST Pandas project itself does not implement any sanitization or encoding of data to prevent CSV injection in Excel renderers. The data from the Django application is directly passed to the pandas `to_excel` function, which includes it in the Excel file without any built-in protection against formula injection.

- **Missing mitigations:**
    - Input sanitization: Implement input validation and sanitization to prevent users from injecting special characters or formula prefixes (like `=, @, +, -`) that can be interpreted as formulas by spreadsheet applications. This sanitization should be applied to any user-controlled data that ends up in the exported Excel file.
    - Contextual encoding:  Pandas `to_excel` function offers options for string escaping, but these are not utilized by default in Django REST Pandas. Explore using these options to properly encode data being written to Excel files to prevent formula injection. For instance,  prepending a single quote (`'`) to strings starting with formula injection characters can prevent them from being interpreted as formulas.
    - Documentation: Clearly document the potential CSV injection vulnerability in the context of Excel exports and advise developers on how to sanitize data before serving it through Django REST Pandas, especially when using Excel renderers.

- **Preconditions:**
    - The application must use Django REST Pandas to serve data in Excel format (using `PandasExcelRenderer` or `PandasOldExcelRenderer`).
    - User-controlled data must be included in the exported Excel file without proper sanitization.
    - The attacker needs to trick a user into downloading and opening the exported Excel file.

- **Source code analysis:**
    - File: `/code/rest_pandas/renderers.py`
    - Class `PandasFileRenderer` and its subclasses `PandasExcelRenderer` and `PandasOldExcelRenderer` are responsible for rendering data in Excel formats.
    - The `render_dataframe` method in `PandasBaseRenderer` (parent of `PandasFileRenderer`) calls `function = getattr(data, name)` where `name` is 'to_excel' and `data` is the pandas DataFrame. Then, it executes this function: `function(*args, **kwargs)`.
    - The `get_pandas_args` method in `PandasFileRenderer` returns a list containing the filename: `return [self.filename]`.
    - The `get_pandas_kwargs` method in `PandasBaseRenderer` returns an empty dictionary by default: `return {}`.
    - This means that `dataframe.to_excel(filename)` is called with minimal control over the output format, and without any explicit sanitization of the DataFrame content before writing to the Excel file.
    - The pandas `to_excel()` function, by default, does not sanitize data against formula injection. Therefore, if the DataFrame contains strings starting with characters like '=', '@', '+', or '-', Excel and other spreadsheet software may interpret them as formulas, leading to CSV injection.

    ```python
    # Vulnerable code snippet from /code/rest_pandas/renderers.py (simplified)
    class PandasBaseRenderer(BaseRenderer):
        def render_dataframe(self, data, name, *args, **kwargs):
            function = getattr(data, name) # name is 'to_excel'
            function(*args, **kwargs) # Calls dataframe.to_excel(filename) without sanitization

    class PandasFileRenderer(PandasBaseRenderer):
        def get_pandas_args(self, data):
            return [self.filename] # filename created using mkstemp
    ```

- **Security test case:**
    - Step 1: Setup a Django REST Pandas view that serves data in Excel format and includes user-controlled input. For example, modify `tests/testapp/views.py` to create a new view that takes a 'injection' GET parameter and includes it in the DataFrame.

    ```python
    # Add to tests/testapp/views.py
    class ExcelInjectionView(PandasSimpleView):
        def get_data(self, request, *args, **kwargs):
            injection = request.GET.get('injection', '')
            data = [{'value': injection}]
            return data
    ```
    - Step 2: Add a corresponding URL pattern in `tests/testapp/urls.py`.

    ```python
    # Add to tests/testapp/urls.py
    path("excel_injection", ExcelInjectionView.as_view()),
    ```
    - Step 3: Run the Django development server.
    - Step 4: Craft a malicious URL that includes a CSV injection payload in the `injection` parameter. For example: `http://127.0.0.1:8000/excel_injection.xlsx?injection==cmd|' /C calc'!A0`.
    - Step 5: Access the URL in a browser to download the `excel_injection.xlsx` file.
    - Step 6: Open the downloaded `excel_injection.xlsx` file using Microsoft Excel or LibreOffice Calc.
    - Step 7: Observe that upon opening the file, the calculator application is launched (or a similar command execution occurs depending on the payload and the spreadsheet software). This confirms the CSV injection vulnerability.

### Vulnerability: Server-Side Request Forgery (SSRF) via Unsanitized Station Code

- **Description:**
    - An attacker who can control the value stored in the Station model’s “code” field may supply a malicious value. In the method `load_weather` (located in `tests/weather/models.py`), the URL for downloading weather data is generated by string substitution without any sanitization. This allows an attacker to make the server send requests to arbitrary URLs.
    - **Step-by-step trigger:**
        1. An attacker identifies a way to control the `Station.code` field, for instance through a user-facing form or API endpoint that allows creating or updating Station records.
        2. The attacker crafts a malicious "code" value. This value could be an internal IP address, a hostname of an internal service, or a URL pointing to an attacker-controlled server.
        3. The attacker triggers the `load_weather` method, either directly or indirectly through application functionality that calls this method.
        4. The server, when executing `load_weather`, will construct a URL using the attacker-controlled "code" and make an HTTP request to that URL.

- **Impact:**
    - If exploited, the server will send HTTP requests to arbitrary destinations. This may allow an attacker to:
        - Probe internal network resources (bypassing firewall restrictions).
        - Exfiltrate sensitive information from internal endpoints.
        - Possibly leverage the server as a proxy in further attacks.

- **Vulnerability Rank:** High

- **Currently Implemented Mitigations:**
    - None. The code simply uses string formatting to build the URL without any validation or sanitation of the `code` field.

- **Missing Mitigations:**
    - Validate and restrict the allowed values for the station “code” (for example by using a whitelist or a fixed regular expression).
    - Use URL-parsing or encoding libraries to ensure that any injected special characters are neutralized.
    - Add request timeouts and network egress filtering to prevent abuse.
    - Consider preventing external input from reaching this processing function in a public API.

- **Preconditions:**
    - The attacker must be able to control or set the `Station.code` field. This may occur if the application exposes the station-creating/updating functionality to untrusted users or if an administrator fails to validate input.

- **Source Code Analysis:**
    - File: `tests/weather/models.py`
    - The constant `DATA_URL = "https://www.ncei.noaa.gov/access/past-weather/{code}/data.csv"` is defined.
    - The method `load_weather` calls `response = requests.get(DATA_URL.format(code=self.code))` with no sanitation or verification of `self.code`.
    - The fetched CSV data is parsed and inserted into the weather database.

    ```python
    # Vulnerable code snippet from tests/weather/models.py (simplified)
    DATA_URL = "https://www.ncei.noaa.gov/access/past-weather/{code}/data.csv"

    def load_weather(self):
        response = requests.get(DATA_URL.format(code=self.code)) # No sanitization of self.code
        # ... process response ...
    ```

- **Security test case:**
    - Step 1: Set up a test instance using the same code (or a similar derived application) that exposes the Station creation endpoint.
    - Step 2: Create (or update) a Station record with a malicious “code” value (for example, a value containing a domain name/IP address known to be internal or under attacker control, or with additional CRLF characters to attempt URL manipulation). For example, set `code` to `http://localhost:8000/internal-admin-page` if such page exists.
    - Step 3: Trigger the `load_weather` method (either via an API call or by directly calling the method in a test).
    - Step 4: Monitor outbound HTTP requests from the server. If the request is made to the attacker-specified endpoint (or for unexpected destinations), the vulnerability is confirmed. In the example of `http://localhost:8000/internal-admin-page`, you can check server logs to see if a request to `/internal-admin-page` was made from within the server.

### Vulnerability: HTTP Header Injection in Content-Disposition Header

- **Description:**
    - When a pandas-based view is rendered, the helper method `get_pandas_headers` in the `PandasMixin` (located in `rest_pandas/views.py`) constructs a “Content-Disposition” header by directly embedding the filename obtained from `get_pandas_filename`. If `get_pandas_filename` returns a string containing newline characters or CRLF sequences, an attacker can inject arbitrary HTTP headers.
    - **Step-by-step trigger:**
        1. An attacker identifies a way to influence the filename returned by the `get_pandas_filename` method. This could be through URL parameters, database values, or any other input that a developer might use to dynamically generate filenames.
        2. The attacker crafts a malicious filename string that includes CRLF sequences followed by headers they wish to inject. For example: `report.csv\r\nInjected-Header: malicious-value`.
        3. The attacker makes a request to the vulnerable endpoint, ensuring that their malicious filename (or the input that leads to it) is used by the application.
        4. The server processes the request, and the `get_pandas_headers` method constructs the `Content-Disposition` header using the malicious filename.
        5. The server sends the HTTP response. Due to the CRLF injection in the filename, the attacker's injected headers are also included in the response.

- **Impact:**
    - The attacker could use HTTP header injection (or response splitting) to:
        - Manipulate HTTP responses.
        - Poison caches.
        - In some cases combine with subsequent XSS attacks to inject scripts (though less directly via Content-Disposition).

- **Vulnerability Rank:** High

- **Currently Implemented Mitigations:**
    - The default implementations provided by sample views return fixed, hardcoded filenames. However, there is no sanitation at the library level in `get_pandas_headers` to ensure that malicious characters are stripped from the filename.

- **Missing Mitigations:**
    - Sanitize the filename by stripping any newline (`\n` / `\r`) characters or other control sequences before including it in the header.
    - Use defensive coding or built-in libraries (or even Django’s own utilities) to safely quote header values.
    - Optionally ignore or override any user-supplied filename if it is not from a trusted source.

- **Preconditions:**
    - An attacker must be able to influence the return value of `get_pandas_filename`. This will be possible if the application (or a developer’s override) uses unsanitized external input (such as GET parameters or database values) to form the filename.

- **Source Code Analysis:**
    - File: `rest_pandas/views.py`
    - In the base class `PandasMixin`, the method `get_pandas_headers` is defined.
    - It directly uses the return from `get_pandas_filename` (which is not sanitized in the project code) to construct the header via Python’s string formatting:  `'attachment; filename="{}"'.format(filename)`.
    - No extra checks (such as filtering CR or LF characters) are performed.

    ```python
    # Vulnerable code snippet from rest_pandas/views.py (simplified)
    class PandasMixin:
        def get_pandas_headers(self, request):
            filename = self.get_pandas_filename(request, format)
            if filename:
                return {
                    "Content-Disposition": 'attachment; filename="{}"'.format(filename) # No filename sanitization
                }
            return {}
    ```

- **Security test case:**
    - Step 1: Create or override a view so that its `get_pandas_filename` method returns a string containing CRLF sequences (for example: `filename = 'report.csv\r\nInjected: malicious-header: evil'`).
    - Step 2: Invoke the vulnerable endpoint with an HTTP client (e.g., `curl -v http://127.0.0.1:8000/your-view`).
    - Step 3: Examine the raw HTTP response headers to see if extra headers are injected. In the example filename, you should see an additional header `Injected-Header: malicious-value` in the HTTP response headers.
    - Step 4: If the header is split or additional header content appears, the vulnerability is confirmed.

### Vulnerability: Lack of Integrity Verification for External JavaScript Dependencies in GitHub Pages Workflow

- **Description:**
    - The project’s GitHub Pages build workflow (in `.github/workflows/pages.yml`) downloads several JavaScript files directly from unpkg.com using `curl` without any integrity verification. This means if unpkg.com or the delivery path is compromised, malicious JavaScript code could be injected into the project's documentation site.
    - **Step-by-step trigger:**
        1. An attacker compromises the unpkg.com CDN, or performs a man-in-the-middle attack during the download process.
        2. When the GitHub Pages workflow runs, the `curl` commands fetch the attacker's malicious JavaScript code instead of the legitimate libraries.
        3. The workflow proceeds to build and deploy the documentation site using the compromised JavaScript files.
        4. Users visiting the GitHub Pages documentation site will execute the malicious JavaScript code in their browsers.

- **Impact:**
    - An attacker who can compromise the external host could modify the JavaScript files. This could lead to:
        - Injection of malicious code into the client-side assets.
        - Cross-site scripting (XSS) attacks on users who visit the GitHub Pages site.
        - Broad supply-chain compromise of the web asset.

- **Vulnerability Rank:** Critical

- **Currently Implemented Mitigations:**
    - None. The workflow downloads the scripts over HTTPS but does not perform any additional integrity checks (such as verifying expected checksums or using hard-coded SRI hashes).

- **Missing Mitigations:**
    - Pin the external dependencies to explicit versions and verify them using SHA256 or SRI checksums. For example, instead of `@latest` or `@next`, use specific versions like `@wq/markdown@1.2.3` and obtain SRI hashes for these versions from reputable sources.
    - Implement a post-download checksum comparison in the workflow before committing the files to the site.
    - Alternatively, vendor and maintain the JavaScript dependencies in a secure repository, committing them directly into the project instead of downloading them during build time.

- **Preconditions:**
    - An attacker must be able to compromise the unpkg.com-hosted versions of the dependencies or intercept the connection even over HTTPS (for example, by exploiting weaknesses in the CDN or through DNS hijacking).

- **Source Code Analysis:**
    - File: `.github/workflows/pages.yml`
    - The workflow file downloads JS files using `curl` with no integrity validation:
    ```yaml
    curl -L -s https://unpkg.com/wq > docs/js/wq.js
    curl -L -s https://unpkg.com/@wq/markdown@latest > docs/js/markdown.js
    curl -L -s https://unpkg.com/@wq/analyst@next > docs/js/analyst.js
    curl -L -s https://unpkg.com/@wq/chart@next > docs/js/chart.js
    ```
    - Subsequent `sed` commands rewrite module import paths but do not alter the contents or perform any security checks.
    - The downloaded files are placed under `docs/js/` and are then served to visitors.

- **Security test case:**
    - Step 1: In a controlled test environment, create a simple HTTP server that mimics unpkg.com and serves a malicious JavaScript file when requested for one of the dependencies (e.g., `wq.js`).
    - Step 2: Modify the `.github/workflows/pages.yml` file to point the `curl` command to your malicious server instead of unpkg.com.
    - Step 3: Run the Pages workflow locally or simulate its steps so that the modified file is "downloaded" from your server.
    - Step 4: Visit the generated documentation site (served locally or from the workflow output) and check whether the malicious JavaScript executes (for example, by triggering an alert or logging a known token to the console).
    - Step 5: Validate that without an integrity check, the site's asset pipeline accepts altered remote files. To further confirm, revert the workflow and manually replace the downloaded `wq.js` in `docs/js/` with your malicious version and check if it executes when you open `docs/index.html`.