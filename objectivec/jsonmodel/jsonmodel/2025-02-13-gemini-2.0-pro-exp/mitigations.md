# Mitigation Strategies Analysis for jsonmodel/jsonmodel

## Mitigation Strategy: [Strict Type Enforcement and Whitelisting within `jsonmodel`](./mitigation_strategies/strict_type_enforcement_and_whitelisting_within__jsonmodel_.md)

**Mitigation Strategy:**  Rigorous type hinting and data validation within `jsonmodel` class definitions.

*   **Description:**
    1.  **Define `jsonmodel` Classes:** Create Python classes that inherit from `jsonmodel.JSONModel`.
    2.  **Use Specific Type Hints:** For *every* attribute, use the most precise type hint available from `pydantic` (the foundation of `jsonmodel`).  Avoid generic types like `str`, `int`, `list`, `dict`. Instead, use:
        *   `constr(min_length=..., max_length=..., regex=...)`: For strings with specific constraints.
        *   `conint(gt=..., lt=..., ge=..., le=...)`: For integers with specific ranges.
        *   `confloat(gt=..., lt=..., ge=..., le=...)`: For floats with specific ranges.
        *   `conlist(item_type=..., min_items=..., max_items=...)`: For lists, specifying the type of items and optionally the minimum/maximum number of items.
        *   `conset(item_type=..., min_items=..., max_items=...)`: For sets.
        *   `conbytes(min_length=..., max_length=...)`: For byte strings.
        *   `condecimal(...)`: For decimal numbers.
        *   `EmailStr`: For email addresses (from `pydantic`).
        *   `HttpUrl`: For URLs (from `pydantic`).
        *   `UUID`: For UUIDs (from `pydantic`).
        *   ...and other constrained types as appropriate.
    3.  **Use `Field` with `alias` and Required Status:**
        *   Use `pydantic.Field` for *every* attribute.
        *   Set the `alias` parameter in `Field` if the JSON key name differs from the Python attribute name. This helps obscure internal attribute names.
        *   Use `...` (Ellipsis) as the first argument to `Field` to make the field *required*.  If the field is optional, set a default value (e.g., `Field(None)`).
    4.  **Create Custom Validators (`@validator`):**
        *   Use `@validator` decorators (from `pydantic`) to define custom validation functions for attributes that need more complex checks than simple type constraints.
        *   Within validators:
            *   **Whitelist:** Check against allowed values (lists, sets, enums).
            *   **Enforce Formats:** Use regular expressions or other logic to validate data formats (dates, custom patterns).
            *   **Raise `ValueError`:**  If validation fails, *always* raise a `ValueError`.  Do *not* attempt to sanitize or modify the data within the validator (rejection is preferred).
    5.  **Set `extra = 'forbid'` in `Config`:**
        *   Inside your `jsonmodel` class, define a nested `Config` class.
        *   Set `extra = 'forbid'` within the `Config` class.  This is *crucial* to prevent attackers from injecting arbitrary, undefined attributes into your model.
    6. **Example:**
        ```python
        from jsonmodel import JSONModel, Field
        from pydantic import constr, validator, EmailStr, conint

        class User(JSONModel):
            user_id: int = Field(..., alias="id")  # Required, aliased
            username: constr(min_length=3, max_length=20, regex="^[a-zA-Z0-9_]+$")
            email: EmailStr = Field(..., alias="email_address") # Required, aliased
            age: conint(ge=18, le=120) = Field(None)  # Optional, with range
            roles: list[str] = Field(...)

            @validator('roles')
            def validate_roles(cls, v):
                allowed_roles = ["user", "admin", "guest"]
                if not all(role in allowed_roles for role in v):
                    raise ValueError("Invalid role(s)")
                return v

            class Config:
                extra = 'forbid'
        ```

*   **List of Threats Mitigated:**
    *   **Type Confusion:** (Severity: High) - Prevents injection of unexpected data types.
    *   **Prototype Pollution:** (Severity: Low in Python) - Mitigates, though less relevant in Python.
    *   **Denial of Service (DoS) - Data Size:** (Severity: Medium) - Limits string/array lengths via `constr`, `conlist`, etc.
    *   **Code Injection (Indirect):** (Severity: High) - Reduces the risk of injected data being used unsafely later.
    *   **Unexpected Attribute Injection:** (Severity: Medium) - `extra = 'forbid'` prevents adding undefined attributes.

*   **Impact:**
    *   **Type Confusion:** Risk significantly reduced.
    *   **Prototype Pollution:** Risk remains low, further mitigated.
    *   **DoS (Data Size):** Risk significantly reduced (within the scope of `jsonmodel`).
    *   **Code Injection (Indirect):** Risk significantly reduced (relies on secure coding elsewhere).
    *   **Unexpected Attribute Injection:** Risk eliminated.

*   **Currently Implemented:** [Describe where this is implemented in your project, e.g., "Implemented in all new `jsonmodel` classes.  We are refactoring older models to use this approach."]

*   **Missing Implementation:** [Describe where this is missing, e.g., "The `LegacyData` model still uses basic types and lacks `extra = 'forbid'`.  Some validators are missing for complex fields."]

## Mitigation Strategy: [Careful `__init__` and Custom Method Handling (Within `jsonmodel`)](./mitigation_strategies/careful____init____and_custom_method_handling__within__jsonmodel__.md)

**Mitigation Strategy:**  Minimize logic in `__init__` and validate inputs to custom methods *defined within* the `jsonmodel` class.

*   **Description:**
    1.  **Prefer `@validator` over `__init__`:**  Avoid putting complex data transformation or validation logic directly in the `__init__` method of your `jsonmodel` classes.  The primary purpose of `__init__` should be simple attribute assignment.
    2.  **Use `@validator` for Pre-processing:**  Use `@validator` decorators to handle any logic that needs to run *before* the object is fully initialized.  Validators are executed in the order they are defined, *before* `__init__` is called.
    3.  **Validate Inputs to Custom Methods:** If your `jsonmodel` class defines custom methods (other than `__init__`):
        *   **Treat Inputs as Untrusted:**  Even if the input comes from the model's own attributes, treat it as potentially untrusted within the custom method.
        *   **Perform Validation:**  Before using any data within the custom method, perform thorough validation.  This might involve:
            *   Re-using existing `@validator` functions (if applicable).
            *   Checking types.
            *   Checking value ranges.
            *   Validating formats.
            *   Raising `ValueError` on failure.
        *   **Example:**
            ```python
            from jsonmodel import JSONModel
            from pydantic import validator, constr

            class Product(JSONModel):
                name: str
                price: float

                @validator('price')
                def price_must_be_positive(cls, v):
                    if v < 0:
                        raise ValueError("Price cannot be negative")
                    return v

                def discounted_price(self, discount_percentage: float) -> float:
                    # Validate discount_percentage even though it's type-hinted
                    if not 0 <= discount_percentage <= 1:
                        raise ValueError("Discount percentage must be between 0 and 1")
                    return self.price * (1 - discount_percentage)
            ```

*   **List of Threats Mitigated:**
    *   **Code Injection (Indirect):** (Severity: High) - Prevents vulnerabilities in custom methods that might use unvalidated data unsafely.
    *   **Logic Errors:** (Severity: Medium) - Reduces unexpected behavior due to invalid data within custom methods.

*   **Impact:**
    *   **Code Injection (Indirect):** Risk reduced (depends on the specific logic in custom methods).
    *   **Logic Errors:** Risk reduced.

*   **Currently Implemented:** [Describe implementation, e.g., "We avoid complex logic in `__init__`. Custom methods in `jsonmodel` classes have input validation."]

*   **Missing Implementation:** [Describe missing areas, e.g., "Some older `jsonmodel` classes have logic in `__init__` that needs refactoring.  A few custom methods lack complete input validation."]

