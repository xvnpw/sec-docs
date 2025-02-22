### Vulnerability List

- Vulnerability Name: CSV Injection in Excel Renderers
- Description:
    - An attacker can inject malicious formulas into CSV data served by Django REST Pandas when using Excel renderers (PandasExcelRenderer, PandasOldExcelRenderer).
    - When a user opens the exported Excel file, these injected formulas can be executed by Excel.
    - Step-by-step trigger:
        1. An attacker identifies an API endpoint in a Django REST Pandas application that exports data in Excel format (e.g., `/api/data.xlsx`).
        2. The attacker crafts a request to this endpoint such that the data returned by the API, and subsequently included in the exported Excel file, contains a CSV injection payload. This could be achieved by manipulating input parameters that influence the data being processed by the API. For example, if the API endpoint displays data based on a search query, the attacker could include the payload in the search query. A common CSV injection payload for Excel is `=cmd|' /C calc'!A0` which attempts to execute the calculator application.
        3. The server processes the request and generates an Excel file containing the injected payload.
        4. The attacker tricks a user into downloading and opening the malicious Excel file.
        5. When the user opens the Excel file, Excel interprets the injected string as a formula and executes it. In the example payload `=cmd|' /C calc'!A0`, this would lead to the execution of the `calc` command, opening the calculator application on the user's system. More dangerous commands could also be injected.
- Impact:
    - Arbitrary command execution on the victim's machine when they open the exported Excel file.
    - Depending on the injected formula, this could lead to:
        - Information disclosure: attacker could potentially read local files or system information.
        - Data exfiltration: attacker could send sensitive data to an external server.
        - System compromise: in more advanced scenarios, attacker might be able to gain persistent access to the user's system.
- Vulnerability Rank: High
- Currently implemented mitigations:
    - None. The Django REST Pandas project itself does not implement any sanitization or encoding of data to prevent CSV injection in Excel renderers. The data from the Django application is directly passed to the pandas `to_excel` function, which includes it in the Excel file without any built-in protection against formula injection.
- Missing mitigations:
    - Input sanitization: Implement input validation and sanitization to prevent users from injecting special characters or formula prefixes (like `=, @, +, -`) that can be interpreted as formulas by spreadsheet applications. This sanitization should be applied to any user-controlled data that ends up in the exported Excel file.
    - Contextual encoding:  Pandas `to_excel` function offers options for string escaping, but these are not utilized by default in Django REST Pandas. Explore using these options to properly encode data being written to Excel files to prevent formula injection. For instance,  prepending a single quote (`'`) to strings starting with formula injection characters can prevent them from being interpreted as formulas.
    - Documentation: Clearly document the potential CSV injection vulnerability in the context of Excel exports and advise developers on how to sanitize data before serving it through Django REST Pandas, especially when using Excel renderers.
- Preconditions:
    - The application must use Django REST Pandas to serve data in Excel format (using `PandasExcelRenderer` or `PandasOldExcelRenderer`).
    - User-controlled data must be included in the exported Excel file without proper sanitization.
    - The attacker needs to trick a user into downloading and opening the exported Excel file.
- Source code analysis:
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

- Security test case:
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