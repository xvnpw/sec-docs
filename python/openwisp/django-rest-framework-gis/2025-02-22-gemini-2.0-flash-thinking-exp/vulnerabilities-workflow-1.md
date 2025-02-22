## Vulnerability List

- Vulnerability Name: Resource Exhaustion via Complex Geometry Parsing
- Description:
An attacker can cause resource exhaustion by sending a crafted request with an extremely complex geometric payload to an API endpoint that uses `GeometryField` for deserialization. The `GeometryField` utilizes `GEOSGeometry` to parse the input geometry from various formats (GeoJSON, WKT, EWKT, HEXEWKB). Parsing highly complex geometries, such as polygons with a very large number of vertices or deeply nested geometry collections, can consume excessive CPU and memory resources on the server, potentially impacting the application's responsiveness and availability for other users.

  - Step-by-step trigger:
    1. Identify an API endpoint that accepts GeoJSON, WKT, EWKT, or HEXEWKB input and uses `GeometryField` to process it. For example, the `GeojsonLocationList` endpoint in `tests/django_restframework_gis_tests/urls.py` and `tests/django_restframework_gis_tests/views.py` which uses `LocationGeoFeatureSerializer` with `GeometryField`.
    2. Construct a GeoJSON payload representing an extremely complex geometry. This could be a Polygon with tens of thousands of vertices, a very deep GeometryCollection, or a MultiPolygon with a huge number of polygons and vertices.
    3. Send a POST or PUT request to the identified API endpoint with the crafted, complex GeoJSON payload in the request body.
    4. Observe the server's resource consumption. Repeated requests with such payloads can lead to significant CPU and memory usage, potentially slowing down or crashing the application.

  - Impact:
    Resource exhaustion on the server leading to:
        - Slow API response times for all users.
        - Potential temporary unavailability of the API endpoint or the entire application.
        - Increased server load and operational costs.

  - Vulnerability Rank: High

  - Currently Implemented Mitigations:
    None. The code directly parses the input geometry using `GEOSGeometry` without any explicit checks on its complexity or size.

  - Missing Mitigations:
    - Input validation and sanitization: Implement checks to limit the complexity and size of incoming geometries before parsing them with `GEOSGeometry`. This could include:
        - Limiting the number of vertices in polygons and linestrings.
        - Limiting the depth of geometry collections.
        - Setting maximum allowed size for the geometry string in bytes.
    - Request rate limiting: Implement rate limiting on API endpoints that accept geometry input to reduce the impact of rapid, malicious requests.
    - Resource limits: Configure resource limits (CPU, memory) for the application to prevent a single request from consuming excessive resources and affecting the entire system.

  - Preconditions:
    - An API endpoint is exposed that uses `GeometryField` to deserialize geometry data from user input (e.g., POST or PUT requests).
    - The application is deployed in an environment where resource exhaustion can impact performance and availability.

  - Source Code Analysis:
    1. File: `/code/rest_framework_gis/fields.py`
    2. Function: `GeometryField.to_internal_value(self, value)`
    3. Line:
    ```python
            try:
                return GEOSGeometry(value)
            except GEOSException:
                raise ValidationError(
                    _(
                        'Invalid format: string or unicode input unrecognized as GeoJSON, WKT EWKT or HEXEWKB.'
                    )
                )
            except (ValueError, TypeError, GDALException) as e:
                raise ValidationError(_(f'Unable to convert to python object: {str(e)}'))
    ```
    4. Analysis:
        - The `to_internal_value` method is responsible for converting the input `value` (which comes from the request) into a `GEOSGeometry` object.
        - It directly uses `GEOSGeometry(value)` to perform the parsing.
        - There are `try-except` blocks to catch parsing errors (`GEOSException`, `ValueError`, `TypeError`, `GDALException`) and raise `ValidationError` if parsing fails due to invalid format.
        - **Crucially, there are no checks on the complexity or size of the `value` before passing it to `GEOSGeometry`.** This means that if a valid but extremely complex geometry string is provided, `GEOSGeometry` will attempt to parse it, potentially consuming significant resources.
        - The lack of validation on geometry complexity allows an attacker to send requests with computationally expensive geometries, leading to resource exhaustion.

  - Security Test Case:
    1. Prepare a complex GeoJSON Polygon payload. A simple way to create a complex polygon is to generate a large number of vertices that form a complex shape. For example, you can generate a polygon with 50,000 vertices. You can use online tools or scripts to generate such GeoJSON. Example Python script to generate a large polygon (you may need to install `geojson` library: `pip install geojson`):
    ```python
    import geojson

    num_vertices = 50000
    vertices = []
    for i in range(num_vertices):
        angle = (i / num_vertices) * 360
        import math
        x = 0 + 10 * math.cos(math.radians(angle))
        y = 0 + 10 * math.sin(math.radians(angle))
        vertices.append((x, y))

    complex_polygon = geojson.Polygon([vertices])
    geojson_payload = geojson.dumps(complex_polygon)

    with open('complex_polygon.geojson', 'w') as f:
        f.write(geojson_payload)

    print("Complex GeoJSON payload saved to complex_polygon.geojson")
    ```
    2. Identify the `GeojsonLocationList` endpoint URL (e.g., `/geojson/`).
    3. Use `curl` or a similar tool to send a POST request to the endpoint with the complex GeoJSON payload. Replace `<API_ENDPOINT_URL>` with the actual URL of your test instance.
    ```bash
    curl -X POST \
         -H "Content-Type: application/json" \
         -d @complex_polygon.geojson \
         <API_ENDPOINT_URL>
    ```
    4. Monitor the server's CPU and memory usage during the request processing. You should observe a significant increase in resource consumption compared to normal requests with simple geometries.
    5. Repeat step 3 multiple times in quick succession. Observe if the server's responsiveness degrades or if it becomes temporarily unavailable.
    6. Expected result: The server should exhibit high CPU and/or memory usage when processing the complex geometry. Repeated requests should exacerbate the resource exhaustion, potentially leading to slow responses or temporary unavailability, demonstrating the vulnerability.

- Vulnerability Name: Hardcoded Secret Key in Test Settings
- Description:
The file `/code/tests/settings.py` hard‐codes a secret key (`SECRET_KEY = 'fn)t*+$)ugeyip6-#txyy$5wf2ervc0d2n#h)qb)y5@ly$t*@w'`). If, by mistake, these test settings (or a derivative of them) are deployed to a publicly available production instance, an attacker knowing the secret key can forge cryptographic signatures (e.g. session cookies, password reset tokens) to impersonate users or escalate privileges.

  - Step-by-step trigger:
    1. Analyze the publicly visible source code repository to retrieve the hardcoded secret key from `/code/tests/settings.py`.
    2. Deploy the application using the test settings in a production environment (misconfiguration).
    3. As an attacker, use the known secret key to forge a valid session cookie or authentication token.
    4. Attempt to access authenticated endpoints—if successful, this confirms that the application is vulnerable to session hijacking.

  - Impact:
    An attacker can hijack authenticated sessions, potentially bypass security measures, and perform unauthorized actions. This may result in account takeover and circumvention of integrity checks.

  - Vulnerability Rank: High

  - Currently Implemented Mitigations:
    There is no mechanism in the repository to load a secret value from a secure environment source for these settings. (Note: the secret key is only defined in test settings, but if mis‐used in production, it represents a risk.)

  - Missing Mitigations:
    - Use environment variables (or a secrets management system) to inject a production-appropriate secret key.
    - Separate production settings from test/development settings so that a hard-coded key is never deployed.

  - Preconditions:
    The application is inadvertently deployed using these test settings (or a misconfigured settings module that still carries the hard-coded key) in a production environment.

  - Source Code Analysis:
    - In `/code/tests/settings.py` the secret key is defined as:
      `SECRET_KEY = 'fn)t*+$)ugeyip6-#txyy$5wf2ervc0d2n#h)qb)y5@ly$t*@w'`
      This string is directly embedded in source code and is publicly visible in the repository.

  - Security Test Case:
    1. Deploy the application using the test settings.
    2. As an external attacker, analyze the publicly visible source code to retrieve the secret key.
    3. Use the known secret key to forge a valid session cookie or authentication token.
    4. Attempt to access authenticated endpoints—if successful, this confirms that the application is vulnerable to session hijacking.

- Vulnerability Name: DEBUG Mode Enabled in Test Settings
- Description:
In `/code/tests/settings.py`, the setting `DEBUG = True` is enabled. If these settings are mistakenly used in production, any error or exception will reveal sensitive technical details such as stack traces, configuration details, and other internal information.

  - Step-by-step trigger:
    1. Access an endpoint with a URL that is known not to exist on a publicly deployed instance using test settings.
    2. Observe the server response.

  - Impact:
    Detailed error pages could expose internal application structure, file paths, and even portions of the database schema. Such information can greatly assist an attacker in planning further attacks.

  - Vulnerability Rank: High

  - Currently Implemented Mitigations:
    The file is intended for test purposes only; no production fallback exists in these files.

  - Missing Mitigations:
    - Ensure that production settings always set `DEBUG = False`.
    - Adopt a settings management strategy (for example, using environment variables) to differentiate between production and test environments.

  - Preconditions:
    The publicly available instance is inadvertently deployed using these test settings.

  - Source Code Analysis:
    - In `/code/tests/settings.py`, the file explicitly sets `DEBUG = True` (and also `TEMPLATE_DEBUG = DEBUG`), which will cause verbose error messages on unhandled exceptions.

  - Security Test Case:
    1. Access an endpoint with a URL that is known not to exist.
    2. Confirm that the response is a verbose error page containing details (such as the stack trace, file paths, etc.).
    3. Document any internal information exposed as evidence of the vulnerability.

- Vulnerability Name: Unrestricted File Upload in LocatedFile Endpoints
- Description:
The model `LocatedFile` (defined in `/code/tests/django_restframework_gis_tests/models.py`) has a file field declared as: `file = models.FileField(upload_to='located_files', blank=True, null=True)` Its corresponding serializer (in `/code/tests/django_restframework_gis_tests/serializers.py`) uses a plain `serializers.FileField` without any additional validation of file type, size, or content. An external attacker could use an update (or create) endpoint that handles `LocatedFile` objects to upload a file containing dangerous content.

  - Step-by-step trigger:
    1. Identify an API endpoint that allows creation or update of `LocatedFile` objects.
    2. Prepare a request to this endpoint.
    3. Include a file upload with a filename that mimics a dangerous extension (e.g. `malicious.php` or `shell.html`) and with content containing a known payload.
    4. Send the request.
    5. Verify that the file is accepted and stored.
    6. Attempt to access the uploaded file URL and confirm that its content is served as uploaded.

  - Impact:
    If an attacker uploads a file that contains executable code (for example, a script with webshell code) and if the server is misconfigured to serve MEDIA files as executable (or if another process later mistakenly processes the file), this can lead to remote code execution or further compromise of the system.

  - Vulnerability Rank: High

  - Currently Implemented Mitigations:
    No file validation (such as file type or size restrictions) is applied.

  - Missing Mitigations:
    - Implement strict file type and file size validations in the serializer or model level.
    - Store uploaded files in a directory that is not served as executable code by the web server.
    - Consider scanning uploaded files for malware.

  - Preconditions:
    - The API endpoint accepting updates or creation of `LocatedFile` records is publicly accessible without proper authorization or file validation.
    - The deployment configuration does not prevent execution of uploaded files.

  - Source Code Analysis:
    - In `/code/tests/django_restframework_gis_tests/models.py`, the `LocatedFile` model defines the file field without validators.
    - In `/code/tests/django_restframework_gis_tests/serializers.py`, the serializer for `LocatedFile` simply exposes the file field as is.

  - Security Test Case:
    1. Prepare a test request that targets the endpoint associated with `LocatedFile` (for example, via a PATCH or PUT request using DRF’s update endpoint).
    2. In the request payload, include a file upload with a filename that mimics a dangerous extension (e.g. `malicious.php` or `shell.html`) and with content containing a known payload (this should be performed safely in a test environment).
    3. Send the request and verify that the file is accepted and stored.
    4. If possible, attempt to access the uploaded file URL and confirm that its content is served as uploaded—demonstrating the risk of arbitrary file upload.

- Vulnerability Name: Detailed Internal Error Disclosure in Geometry Parsing
- Description:
The custom `GeometryField` (defined in `/code/rest_framework_gis/fields.py`) converts incoming geometry values using `GEOSGeometry(value)`. When an input cannot be parsed, exceptions such as `GEOSException` and others (like `ValueError` or `GDALException`) are caught and then re‐raised as a `ValidationError` with an error message that embeds the original exception’s string value. An attacker could deliberately submit malformed or invalid geometry data to trigger these error messages, which might reveal underlying library details or internal processing logic.

  - Step-by-step trigger:
    1. Craft an HTTP request to an endpoint that accepts geometry input (for example, a POST to create a new Location).
    2. In the request payload, set the geometry field value to a deliberately malformed string (for example, `"I AM NOT A GEOMETRY"`).
    3. Send the request.
    4. Observe the error message in the response.

  - Impact:
    Exposing internal error details (for example, specific exception messages and potentially stack trace excerpts) can provide an attacker with valuable information about the internals of the geometry processing logic, versions of libraries in use, and even hints as to possible further attack vectors.

  - Vulnerability Rank: High

  - Currently Implemented Mitigations:
    The code does perform input conversion and exception handling but does not sanitize the content of error messages.

  - Missing Mitigations:
    - Modify the error handling so that only generic, non-developer error messages are returned (e.g. “Invalid geometry input” without including `str(e)`).
    - Log the detailed exception internally while returning a sanitized error message to the client.

  - Preconditions:
    The geometry input is processed via public API endpoints (for example, during create or update operations on resources using a `GeometryField`), and the application returns detailed error messages without additional filtering.

  - Source Code Analysis:
    - In `/code/rest_framework_gis/fields.py`, the `to_internal_value` method contains the following block:
      ```python
      try:
          return GEOSGeometry(value)
      except GEOSException:
          raise ValidationError(_('Invalid format: string or unicode input unrecognized as GeoJSON, WKT EWKT or HEXEWKB.'))
      except (ValueError, TypeError, GDALException) as e:
          raise ValidationError(_(f'Unable to convert to python object: {str(e)}'))
      ```
      The second exception clause directly interpolates the caught exception into the error message.

  - Security Test Case:
    1. Craft an HTTP request to an endpoint that accepts geometry input (for example, a POST to create a new Location).
    2. In the request payload, set the geometry field value to a deliberately malformed string (for example, `"I AM NOT A GEOMETRY"`).
    3. Observe the error message in the response—if it includes details from the internal exception (e.g. portions of exception text that mention library functions or internal expectations), the vulnerability is confirmed.
    4. Verify that when the same malformed input is sent in a sanitized (production) environment the error message does not reveal internal details.