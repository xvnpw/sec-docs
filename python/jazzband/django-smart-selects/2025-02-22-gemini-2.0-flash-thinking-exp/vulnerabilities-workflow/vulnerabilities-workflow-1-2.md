- **Vulnerability Name:** Unrestricted Data Exposure via AJAX Endpoints  
  **Description:**  
  The smart selects package uses AJAX endpoints (e.g. via the `/chaining/filter/…` and `/chaining/all/…` URL patterns) to return filtered model data for chained fields. By design these endpoints do not enforce any authentication or permission checks. An external attacker can construct URL requests with valid parameters—such as specifying an app, model, field, and related foreign key information—even if the underlying model data is intended to be restricted. For example, if a model in the project uses a chained field (as documented in the README), an attacker can send a GET request to an endpoint like:  
  `/chaining/filter/test_app/Country/continent/test_app/Location/country/1/`  
  to retrieve the list of country records.  
  **Impact:**  
  - Unauthorized disclosure of model data.  
  - Exposure of internal or sensitive information (such as lists of records or reference data) intended only for authenticated or authorized users.  
  - This could lead to further abuse when an attacker gains insight into valid identifiers or relationships between models.  
  **Vulnerability Rank:** High  
  **Currently Implemented Mitigations:**  
  - In the view functions (in `smart_selects/views.py`), there is a check that verifies whether the target (foreign) model actually contains at least one chained field (i.e. an instance of either a `ChainedForeignKey` or `ChainedManyToManyField`). If this check fails, a `PermissionDenied` exception is raised.  
  - However, if the model is indeed configured with chained fields—as is expected when using the package—the check passes and no further access control is imposed.  
  **Missing Mitigations:**  
  - There is no authentication or authorization check (e.g. decorators such as `@login_required` or custom permission logic) that ensures that only users with proper rights may call these endpoints.  
  - No mechanism exists to restrict the data returned by these endpoints according to user roles or context.  
  **Preconditions:**  
  - The application is deployed as a public instance where the AJAX endpoints are accessible without additional network or application-level access controls.  
  - Chained fields are used (as is expected by the package and documented in the README) which causes the AJAX endpoints to return data without further verification.  
  **Source Code Analysis:**  
  - In **`smart_selects/views.py`**, the `filterchain` function:  
    - Uses `get_model(app, model)` to dynamically load the model based on URL input.  
    - Calls `get_keywords(field, value, m2m)` to turn URL parameters into a filter for the queryset.  
    - Retrieves the foreign model class (via `get_model(foreign_key_app_name, foreign_key_model_name)`) and then checks if at least one field on that class is an instance of either `ChainedForeignKey` or `ChainedManyToManyField`. If no such field exists, it raises `PermissionDenied`; otherwise, it proceeds.  
    - No check is made against the current user’s authentication or permissions.  
  - The same design applies to the `filterchain_all` function which is nearly identical in its access-flow and filtering logic.  
  - Because the only “gate” is whether the model configuration contains a chained field, any attacker who knows or guesses a valid combination can retrieve data from the endpoint.  
  **Security Test Case:**  
  1. **Step 1:** Identify a valid chained field configuration.  
     - For example, review publicly accessible pages (or documentation) that use the `ChainedForeignKey` for the `Country` model in relation to the `Location` model.
  2. **Step 2:** Craft an HTTP GET request to the filtering endpoint using valid parameters. For instance:  
     ```bash
     curl -X GET "http://<target-domain>/chaining/filter/test_app/Country/continent/test_app/Location/country/1/"
     ```  
  3. **Step 3:** Examine the returned HTTP response.  
     - Expect a JSON response containing a list of country records (e.g., country IDs and display names).  
  4. **Step 4:** Verify that no authentication challenge or permission error occurs and that the data returned is complete and sensitive (or should be protected in your use case).  
  5. **Step 5:** Repeat with the `/chaining/all/...` endpoint to see that even complete lists (possibly including additional data) are returned without restriction.  

Implementing proper permission checks—either by wrapping the endpoint views with authentication/authorization decorators or by integrating access control logic into the smart selects view functions—would be required to mitigate this vulnerability.