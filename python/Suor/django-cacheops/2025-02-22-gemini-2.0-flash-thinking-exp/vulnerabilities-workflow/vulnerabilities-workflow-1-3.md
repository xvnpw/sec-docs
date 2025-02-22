### Vulnerability List

- Vulnerability Name: Conjunctive Key Injection
- Description:
    1. An attacker can create or modify a database record in a Django model that is cached by Cacheops.
    2. The fields of this model are used to generate a conjunctive key for cache invalidation.
    3. If a field value contains special characters like '=' or '&', these characters are not properly escaped when constructing the conjunctive key in the Lua script `invalidate.lua`.
    4. This allows an attacker to inject additional conditions or manipulate the conjunctive key structure.
    5. When the `invalidate_dict` function is called (e.g., on model save or delete), the Lua script `invalidate.lua` will generate incorrect conjunctive keys based on the injected characters.
    6. This can lead to unexpected cache invalidation behavior, potentially causing cache invalidation bypass or incorrect invalidation.
- Impact:
    - Cache invalidation bypass: An attacker might be able to manipulate data in such a way that associated cache entries are not properly invalidated, leading to serving stale data.
    - Cache poisoning: Although less direct, incorrect invalidation could in some scenarios contribute to cache poisoning by making it harder to manage cache consistency.
    - Information disclosure (indirect): Serving stale data could indirectly lead to information disclosure if outdated information is presented to users due to cache invalidation failures.
- Vulnerability Rank: High
- Currently implemented mitigations:
    - None. The code does not currently escape or sanitize field names or values before constructing conjunctive keys in Lua.
- Missing mitigations:
    - **Input Sanitization/Escaping:** In the Lua script `invalidate.lua`, properly escape or encode field names and values before concatenating them to form conjunctive keys. A robust approach would be to use URL-encoding or a similar mechanism to ensure that '=' and '&' characters within field names or values are treated as literal characters and not as delimiters in the conjunctive key structure. Alternatively, consider using a more structured data format (like JSON within Redis sets) for conjunctive keys instead of simple string concatenation.
- Preconditions:
    - Cacheops is enabled and caching Django models.
    - An attacker has the ability to create or modify records in a model that is being cached.
- Source code analysis:
    1. `/code/cacheops/invalidation.py:invalidate_dict`: This function calls `load_script('invalidate')` and passes `model._meta.db_table` and `json.dumps(obj_dict, default=str)` as arguments to the Lua script. The `obj_dict` contains model field names and values.
    2. `/code/cacheops/lua/invalidate.lua:generate_conjs`: This Lua function constructs conjunctive keys by iterating through the `obj_dict` and concatenating `field .. '=' .. value` with '&' as a separator. There is no escaping or encoding of `field` or `value` before concatenation.
    3. **Vulnerable Code Snippet (`/code/cacheops/lua/invalidate.lua`):**
    ```lua
    local function generate_conjs(obj_dict, prefix, table)
        local conjs = {}
        local conj_parts = {}
        for field, value in pairs(obj_dict) do
            table.insert(conj_parts, field .. '=' .. value)
        end
        table.sort(conj_parts)
        table.insert(conjs, table.concat(conj_parts, '&'))
        return conjs
    end
    ```
    4. **Vulnerability:** The `generate_conjs` function in `invalidate.lua` directly concatenates field names and values with `=` and `&` without any encoding. If a field value contains these characters, it can lead to the creation of malformed conjunctive keys, causing incorrect cache invalidation.
- Security test case:
    1. **Setup:**
        - Define a Django model in `tests/models.py`:
        ```python
        class VulnerableModel(models.Model):
            data = models.CharField(max_length=255)
        ```
        - Add Cacheops configuration in `tests/settings.py` to cache `VulnerableModel`:
        ```python
        CACHEOPS = {
            'tests.vulnerablemodel': {'ops': 'all', 'timeout': 60},
            'tests.*': {},
            'auth.*': {},
        }
        ```
        - Create a test case in `tests/tests.py`:
        ```python
        class ConjunctiveKeyInjectionTest(BaseTestCase):
            def test_conjunctive_key_injection(self):
                from .models import VulnerableModel

                # Create and cache an object with a safe value
                safe_obj = VulnerableModel.objects.create(data="safe_value")
                list(VulnerableModel.objects.cache().filter(data="safe_value")) # Cache it

                # Create an object with a malicious value containing '&' and '='
                malicious_obj = VulnerableModel.objects.create(data="malicious=value&extra=condition")

                # Trigger invalidation by saving the malicious object (or could be delete)
                malicious_obj.save()

                # Attempt to retrieve the originally cached safe object.
                # If injection is successful, the cache for 'safe_value' might be incorrectly invalidated.
                with self.assertNumQueries(1): # Expect cache miss due to potential incorrect invalidation
                    list(VulnerableModel.objects.cache().filter(data="safe_value"))
        ```
    2. **Run Test:** Execute the test case.
    3. **Expected Result:** The test `test_conjunctive_key_injection` should fail, showing that when the malicious object is saved, it incorrectly invalidates the cache for the safe object due to the conjunctive key injection vulnerability. The `assertNumQueries(1)` should actually result in more queries (0) if the cache was correctly used, indicating a cache miss and thus incorrect invalidation.