## Vulnerability List

### 1. Information Disclosure via DjangoDebugMiddleware

- **Vulnerability Name:** Information Disclosure via DjangoDebugMiddleware
- **Description:** When `DjangoDebugMiddleware` is enabled in a production environment and the GraphQL schema includes the `DjangoDebug` type (typically exposed as a field named `_debug`), an external attacker can query this `_debug` field to retrieve sensitive debugging information. This includes:
    - **Executed SQL queries:** Full SQL queries executed against the database.
    - **SQL query parameters:** Parameters used in parameterized SQL queries, which can contain sensitive data.
    - **Database Vendor and Alias:** Information about the database system and connection alias.
    - **Query Duration and Performance Metrics:** Timing information for queries.
    - **Stack traces of exceptions:** Detailed stack traces for any exceptions occurring during query execution, revealing internal code paths and potentially sensitive application logic.

    To trigger this vulnerability, an attacker needs to send a GraphQL query to the publicly accessible endpoint that includes the `_debug` field in the query selection set. The middleware, if enabled, will intercept the query execution and append the debug information to the response under the `_debug` field.
- **Impact:** High. Exposure of SQL queries, parameters, and stack traces can lead to significant information disclosure. This information can reveal database schema details, data access patterns, potentially sensitive data within queries, and internal application logic, which can be leveraged for further attacks or unauthorized data access.
- **Vulnerability Rank:** High
- **Currently Implemented Mitigations:**
    - None. The code does not prevent the middleware from being used in production or warn against it.
- **Missing Mitigations:**
    - **Documentation Warning:**  Clear and prominent documentation explicitly warning against enabling `DjangoDebugMiddleware` in production environments due to the risk of information disclosure.
    - **Production Check/Setting:** Implement a mechanism to detect or enforce that `DjangoDebugMiddleware` is not used in production, such as:
        - Checking `settings.DEBUG` and automatically disabling the middleware if `DEBUG=False`.
        - Introducing a dedicated setting (e.g., `GRAPHENE_DEBUG_ENABLED`) to control the middleware's activation, defaulting to `False` in production settings templates.
        - Providing guidance and best practices for securely disabling or removing the `DjangoDebug` field from production GraphQL schemas.
- **Preconditions:**
    - `DjangoDebugMiddleware` must be added to the `MIDDLEWARE` setting in Django's `settings.py`.
    - The GraphQL schema must include the `DjangoDebug` type, typically added as a field named `_debug` to the root `Query` type.
    - The Django application must be deployed in a publicly accessible environment.
- **Source Code Analysis:**
    - `/code/graphene_django/debug/middleware.py`:
        ```python
        class DjangoDebugMiddleware:
            def resolve(self, next, root, info, **args):
                context = info.context
                django_debug = getattr(context, "django_debug", None)
                if not django_debug:
                    if context is None:
                        raise Exception("DjangoDebug cannot be executed in None contexts")
                    try:
                        context.django_debug = DjangoDebugContext()
                    except Exception:
                        raise Exception(
                            "DjangoDebug need the context to be writable, context received: {}.".format(
                                context.__class__.__name__
                            )
                        )
                if info.schema.get_type("DjangoDebug") == info.return_type:
                    return context.django_debug.get_debug_result() # Returns debug info if field type is DjangoDebug
                try:
                    result = next(root, info, **args)
                except Exception as e:
                    return context.django_debug.on_resolve_error(e)
                context.django_debug.add_result(result)
                return result
        ```
        The `DjangoDebugMiddleware.resolve` method checks if the resolved field's return type is `DjangoDebug`. If it is, it directly returns the result of `context.django_debug.get_debug_result()`, which contains the collected debug information (SQL queries, exceptions). This logic is executed unconditionally if the middleware is active and the schema includes the `DjangoDebug` type.
    - `/code/graphene_django/debug/sql/tracking.py` and `/code/graphene_django/debug/exception/formating.py`: These modules are responsible for collecting SQL query details and formatting exception information, respectively, which are then exposed via the `DjangoDebug` type.
    - `/code/graphene_django/debug/types.py`: Defines the `DjangoDebug` GraphQL type, which includes fields like `sql` and `exceptions`, making the debug data accessible via GraphQL queries.
- **Security Test Case:**
    1. Deploy a Django application with `graphene-django` in a publicly accessible test environment.
    2. Modify `settings.py` to include `graphene_django.debug.middleware.DjangoDebugMiddleware` in the `MIDDLEWARE` list:
        ```python
        MIDDLEWARE = [
            # ... other middleware ...
            "graphene_django.debug.middleware.DjangoDebugMiddleware",
        ]
        ```
    3. In your `schema.py`, add the `DjangoDebug` field to your root `Query` type:
        ```python
        import graphene
        from graphene_django import DjangoObjectType
        from graphene_django.debug import DjangoDebug
        from your_app.models import MyModel # Replace with your actual models

        class MyModelType(DjangoObjectType):
            class Meta:
                model = MyModel

        class Query(graphene.ObjectType):
            node = graphene.relay.Node.Field()
            my_model = graphene.Field(MyModelType)
            debug = graphene.Field(DjangoDebug, name='_debug') # Add DjangoDebug field

            def resolve_my_model(root, info):
                return MyModel.objects.first() # Example resolver that triggers a DB query

        schema = graphene.Schema(query=Query)
        ```
    4. Access the GraphiQL interface or use a tool like `curl` to send a GraphQL query to your application's public endpoint:
        ```graphql
        query DebugQuery {
          myModel {
            id
          }
          _debug {
            sql {
              rawSql
              params
            }
            exceptions {
              message
              stack
            }
          }
        }
        ```
    5. Examine the GraphQL response. You should see the `_debug` field in the response data.
    6. Within the `_debug` field, inspect the `sql` list. It should contain entries for the SQL queries executed to resolve the `myModel` field (e.g., the query to fetch `MyModel.objects.first()`). Each SQL entry should include `rawSql` (the SQL query string) and `params` (the query parameters).
    7. If any errors occurred during query resolution, the `exceptions` list in `_debug` will contain details about those exceptions, including `message` and `stack` traces.

    By successfully retrieving SQL queries and potentially exception details via the `_debug` field in a public environment, you have confirmed the Information Disclosure vulnerability.