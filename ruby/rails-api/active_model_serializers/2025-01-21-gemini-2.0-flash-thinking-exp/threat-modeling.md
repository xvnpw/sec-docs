# Threat Model Analysis for rails-api/active_model_serializers

## Threat: [Over-serialization of Sensitive Attributes](./threats/over-serialization_of_sensitive_attributes.md)

**Description:** An attacker might craft API requests or analyze API responses to identify and extract sensitive attributes (e.g., password hashes, internal IDs, private information) that are unintentionally included in the serialized output due to misconfiguration or lack of awareness of what data is being exposed by `active_model_serializers`.

**Impact:** Confidentiality breach, potential for identity theft, unauthorized access to internal systems or data.

**Affected Component:** `ActiveModel::Serializer::Attributes` module, specifically the `attributes` method and its configuration within AMS.

**Risk Severity:** High

**Mitigation Strategies:**
* Explicitly define the attributes to be serialized using the `attributes` method in each serializer.
* Regularly review serializers to ensure only necessary data is exposed.
* Utilize the `except` option within the `attributes` method to explicitly exclude sensitive attributes.
* Employ conditional logic (`if:` or `unless:` options) within `attributes` to control attribute inclusion based on context or user roles.

## Threat: [Exposure of Sensitive Data through Associations](./threats/exposure_of_sensitive_data_through_associations.md)

**Description:** An attacker might exploit API endpoints that use `active_model_serializers` to serialize associated models, gaining access to sensitive data within those associated models. This occurs when associations are included without proper filtering or when the associated serializer (also managed by AMS) exposes more information than intended.

**Impact:** Confidentiality breach, potential for unauthorized access to related resources or data.

**Affected Component:** `ActiveModel::Serializer::Associations` module, specifically the `has_many`, `belongs_to`, and `has_one` methods and their configuration within AMS.

**Risk Severity:** High

**Mitigation Strategies:**
* Carefully consider which associations are necessary to include in the serialized output.
* Use separate serializers for associated models with specific attribute selections tailored to the context.
* Employ the `fields` option within association definitions to limit the attributes serialized for associated models.
* Utilize conditional logic (`if:` option) within association definitions to control when associations are included based on authorization or context.

