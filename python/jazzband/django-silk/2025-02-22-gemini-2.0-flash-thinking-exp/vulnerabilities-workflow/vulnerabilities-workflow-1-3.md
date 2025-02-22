### Vulnerability List

- Vulnerability Name: Local File Inclusion in SQL and Profile Detail Views
- Description:
    1. An attacker can access the Silk UI, assuming authentication and authorization are either disabled or bypassed.
    2. The attacker navigates to the SQL detail view for any captured SQL query (e.g., `/silk/request/<request_id>/sql/<sql_id>/`) or the Profile detail view for any captured profile (e.g., `/silk/profile/<profile_id>/`).
    3. In both SQL and Profile detail views, the traceback might be displayed with file paths. These file paths are made clickable by the `filepath_urlify` template filter, pointing to the respective detail view but with `file_path` and `line_num` parameters in the URL.
    4. An attacker can manually craft a URL to either the SQL or Profile detail view, adding `file_path` and `line_num` GET parameters with arbitrary file paths on the server.
    5. The application, in `silk/views/code.py`'s `_code` function, directly opens and reads the file specified by the `file_path` parameter without any validation or sanitization. This function is called by both `silk/views/sql_detail.py`'s `SQLDetailView` and `silk/views/profile_detail.py`'s `ProfilingDetailView`.
    6. The content of the file is then displayed in the respective detail view within the "Code" section.
- Impact:
    - An external attacker can read arbitrary files from the server's filesystem that the Django application has read permissions to. This could include sensitive source code, configuration files, data files, or environment variables, potentially leading to full server compromise or data breaches.
- Vulnerability Rank: High
- Currently Implemented Mitigations:
    - None. The application directly opens and reads files based on user-provided input without validation in both SQL and Profile detail views.
- Missing Mitigations:
    - Input validation and sanitization for the `file_path` parameter in `silk/views/code.py`'s `_code` function, `silk/views/sql_detail.py`'s `SQLDetailView`, and `silk/views/profile_detail.py`'s `ProfilingDetailView`.
    - Implement proper access control to the Silk UI to restrict access to authorized users only. Enabling `SILKY_AUTHENTICATION` and `SILKY_AUTHORISATION` settings and configuring `SILKY_PERMISSIONS` to restrict access to staff or superuser accounts is crucial.
- Preconditions:
    - Silk is installed and enabled in a Django project.
    - The Silk UI is accessible to the attacker (either `SILKY_AUTHENTICATION` and `SILKY_AUTHORISATION` are disabled, or the attacker has bypassed authentication/authorization).
    - For SQL detail view: There must be at least one SQL query captured by Silk to access the SQL detail view initially and obtain a valid URL structure to modify.
    - For Profile detail view: There must be at least one profile captured by Silk to access the Profile detail view initially and obtain a valid URL structure to modify.
- Source Code Analysis:
    1. **File: /code/silk/views/sql_detail.py**
        ```python
        from silk.views.code import _code

        class SQLDetailView(View):
            # ...
            def get(self, request, *_, **kwargs):
                # ...
                file_path = request.GET.get('file_path', '')
                line_num = int(request.GET.get('line_num', 0))
                # ...
                if pos and file_path and line_num:
                    actual_line, code = _code(file_path, line_num) # [!] file_path from request.GET is passed directly to _code
                    context['code'] = code
                    context['actual_line'] = actual_line
                return render(request, 'silk/sql_detail.html', context)
        ```
        The `SQLDetailView` retrieves the `file_path` parameter directly from the GET request and passes it to the `_code` function.

    2. **File: /code/silk/views/profile_detail.py**
        ```python
        from silk.views.code import _code_context, _code_context_from_request
        ...
        class ProfilingDetailView(View):
            # ...
            def get(self, request, *_, **kwargs):
                # ...
                context['pos'] = pos = int(request.GET.get('pos', 0))
                if pos:
                    context.update(_code_context_from_request(request, prefix='pyprofile_')) # [!] Calls _code_context_from_request which uses _code
        ...
                if file_path and line_num:
                    try:
                        context.update(_code_context(file_path, line_num, profile.end_line_num)) # [!] Calls _code_context which uses _code
                    except OSError as e:
                        ...
        ```
        The `ProfilingDetailView` also uses `_code_context_from_request` and `_code_context`, both of which eventually call the vulnerable `_code` function with user-controlled `file_path`.

    3. **File: /code/silk/views/code.py**
        ```python
        from silk.config import SilkyConfig

        def _code(file_path, line_num, end_line_num=None):
            # ...
            with open(file_path, encoding='utf-8') as f: # [!] file_path is opened without validation
                # ...
                for i, line in enumerate(f):
                    if i in r:
                        lines += line
                    if i + 1 in range(line_num, end_line_num + 1):
                        actual_line.append(line)
            code = lines.split('\n')
            return actual_line, code
        ```
        The `_code` function directly uses the `file_path` argument in `open(file_path, encoding='utf-8')` without any validation.

    4. **Visualization:**

        ```mermaid
        graph LR
            A[User crafts malicious URL with file_path (SQL or Profile Detail)] --> B(SQLDetailView.get / ProfilingDetailView.get);
            B --> C{request.GET.get('file_path')};
            C -- file_path --> D[_code(file_path, line_num)];
            D --> E{open(file_path)};
            E --> F[Read arbitrary file content];
            F --> G(Display file content in Detail View);
            G --> H[Attacker views content];
        ```

- Security Test Case:
    1. Deploy a Django application with django-silk installed and configured (ensure `SILKY_AUTHENTICATION` and `SILKY_AUTHORISATION` are disabled for easy testing, but in a real-world scenario, test after bypassing authentication).
    2. Trigger any Django view that executes at least one SQL query and one profile to ensure there is data in Silk.
    3. Access the Silk UI (e.g., `/silk/`).
    4. **For SQL Detail View:**
        a. Navigate to the "Requests" tab and select any request.
        b. Go to the "SQL" tab for the selected request and click on any SQL query to view its details. This will lead you to the SQL detail view (e.g., `/silk/request/<request_id>/sql/<sql_id>/`).
        c. Observe the URL of the SQL detail page. It should look something like `/silk/request/<request_id>/sql/<sql_id>/`.
        d. Manually modify the URL by adding the `file_path` and `line_num` parameters. For example, to attempt to read `/etc/passwd`, construct a URL like: `/silk/request/<request_id>/sql/<sql_id>/?file_path=/etc/passwd&line_num=1`.
        e. Access the crafted URL in your browser.
        f. Check the "Code" section in the SQL detail view. If the vulnerability exists, you should see the content of the `/etc/passwd` file (or any other file you attempted to read, assuming the Django application has read permissions). If you are testing on Windows, try to read `C:\Windows\win.ini` for example.
        g. If the file content is displayed, the Local File Inclusion vulnerability is confirmed in SQL detail view.
    5. **For Profile Detail View:**
        a. Navigate to the "Profiling" tab and select any profile. This will lead you to the Profile detail view (e.g., `/silk/profile/<profile_id>/`).
        b. Observe the URL of the Profile detail page. It should look something like `/silk/profile/<profile_id>/`.
        c. Manually modify the URL by adding the `file_path` and `line_num` parameters. For example, to attempt to read `/etc/passwd`, construct a URL like: `/silk/profile/<profile_id>/?file_path=/etc/passwd&line_num=1`.
        d. Access the crafted URL in your browser.
        e. Check the "Code" section in the Profile detail view. If the vulnerability exists, you should see the content of the `/etc/passwd` file (or any other file you attempted to read, assuming the Django application has read permissions). If you are testing on Windows, try to read `C:\Windows\win.ini` for example.
        f. If the file content is displayed, the Local File Inclusion vulnerability is confirmed in Profile detail view.
    6. If the file content is displayed in either SQL or Profile detail view, the Local File Inclusion vulnerability is confirmed.