### Vulnerability List:

- Vulnerability Name: Server-Side Template Injection in `TemplateColumn`
- Description:
    - An attacker can inject malicious template code into the `template_code` or `template_name` parameters of the `TemplateColumn`.
    - When the table is rendered and the `TemplateColumn` is processed, the injected template code will be executed by the Django template engine.
    - Step 1: An attacker crafts a request to an application using `django-tables2` that somehow allows control over data rendered in a `TemplateColumn`. This could be through URL parameters, form input, or database content that is displayed in a table.
    - Step 2: The attacker injects malicious Django template code into the controlled data. For example, `{% load os %}{% os.system "malicious command" %}` or similar constructs that execute arbitrary code.
    - Step 3: The application renders the table, and the `TemplateColumn` processes the attacker-controlled template code.
    - Step 4: The Django template engine executes the malicious code, leading to server-side template injection.
- Impact:
    - **Critical**: Full server compromise. An attacker can execute arbitrary code on the server, read sensitive data, modify data, or cause a denial of service. The impact is only limited by the permissions of the user running the Django application.
- Vulnerability Rank: critical
- Currently Implemented Mitigations:
    - None: The code directly uses `Template` and `Context` to render the provided template code without any sanitization or escaping of potentially malicious input.
- Missing Mitigations:
    - Sandboxed template environment: Instead of using the default Django template engine, a sandboxed template environment should be used for rendering `TemplateColumn` content. This would restrict the available template tags and filters, preventing the execution of dangerous code.
- Preconditions:
    - The application using `django-tables2` must be using `TemplateColumn` to render data in tables.
    - An attacker must be able to control the input data that is rendered by the `TemplateColumn` (either directly or indirectly, e.g., through stored data).
- Source Code Analysis:
    - File: `/code/django_tables2/columns/templatecolumn.py`
    - Class: `TemplateColumn`
    - Method: `render`
    - Code snippet:
      ```python
      def render(self, record, table, value, bound_column, **kwargs):
          if self.template:
              template = self.template
          elif self.template_name:
              template = get_template(self.template_name)
          elif self.template_code:
              template = Template(self.template_code) # Vulnerability: Directly using Template on user input
          else:
              return super().render(record=record, table=table, value=value, bound_column=bound_column, **kwargs)

          context = Context(self.get_context_data(
              record=record, table=table, value=value, bound_column=bound_column, extra_context=getattr(table, 'context', None)
          ))
          return template.render(context) # Vulnerability: Rendering template with Context
      ```
    - Visualization:
      ```mermaid
      graph LR
          A[Request with malicious payload] --> B(Application using django-tables2);
          B --> C{Data source with attacker payload for TemplateColumn};
          C --> D[TemplateColumn.render];
          D --> E{Template instantiation with attacker payload: Template(template_code)};
          E --> F[Template engine execution: template.render(Context)];
          F --> G[Server-Side Code Execution];
      ```
    - Step-by-step analysis:
        1. The `TemplateColumn.render` method is called to render a cell in the table.
        2. If `template_code` is provided during `TemplateColumn` initialization, a `Template` object is created directly from `self.template_code`. This is where the vulnerability lies, as `template_code` can be directly controlled by developers using the library, and potentially indirectly by attackers if developers are not careful about data sources.
        3. A `Context` is created, which includes the record, table, value, bound_column, and any extra context from the table.
        4. `template.render(context)` is called, which renders the template using the created context. If the `template_code` contains malicious code, it will be executed at this point.
- Security Test Case:
    - Step 1: Create a Django project and install `django-tables2`.
    - Step 2: Define a Django model that will be used in the table.
    - Step 3: Create a Django view that renders a table.
    - Step 4: Define a `tables.Table` class with a `TemplateColumn`. Pass a template string to `template_code` parameter of `TemplateColumn` which executes system command, e.g., `{% load os %}{{ os.popen "id" }}`. Ensure that the data source for the table allows rendering of this `TemplateColumn`.
    - Step 5: Access the view in a web browser.
    - Step 6: Observe that the output of the `id` command is executed and rendered on the page, demonstrating server-side template injection.