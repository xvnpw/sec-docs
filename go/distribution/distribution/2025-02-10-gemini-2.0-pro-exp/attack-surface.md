# Attack Surface Analysis for distribution/distribution

## Attack Surface: [Malicious Image Uploads](./attack_surfaces/malicious_image_uploads.md)

**Description:** Attackers upload images containing malware, backdoors, or vulnerable components.
    *   **How Distribution Contributes:** The registry's API endpoints (`/v2/<name>/blobs/uploads/`, `/v2/<name>/manifests/<reference>`) are the *direct* mechanism for accepting these uploads. The registry's code handles the upload process and storage.
    *   **Example:** An attacker pushes an image with a known vulnerable web server version, intending to exploit it after deployment.
    *   **Impact:** Compromise of systems running the malicious image, data breaches, lateral movement within the network.
    *   **Risk Severity:** Critical
    *   **Mitigation Strategies:**
        *   **Developers:** Integrate image scanning *before* accepting uploads (this is often done with external tools, but the integration point is within the registry's workflow). Implement robust input validation on manifest and layer data within the registry's code to prevent malformed data from causing issues.

## Attack Surface: [Manifest Manipulation (and Tag Mutability Attacks)](./attack_surfaces/manifest_manipulation__and_tag_mutability_attacks_.md)

**Description:** Attackers modify existing manifests to point to malicious layers or overwrite tags to point to compromised images.
    *   **How Distribution Contributes:** The registry's API endpoints for manifest handling (`/v2/<name>/manifests/<reference>`) are the *direct* target. The registry's code is responsible for storing, serving, and validating manifests. The registry's configuration controls whether mutable tags are allowed.
    *   **Example:** An attacker with write access changes a manifest to replace a legitimate base layer with a backdoored version. Or, they overwrite the `latest` tag to point to a malicious image.
    *   **Impact:** Deployment of compromised images, leading to system compromise, data breaches.
    *   **Risk Severity:** Critical
    *   **Mitigation Strategies:**
        *   **Developers:** Enforce the use of immutable tags (digests) *exclusively* within the registry's configuration options and code. If mutable tags are absolutely necessary, implement strict access controls and auditing within the registry's code. Integrate with Docker Content Trust (Notary) for manifest signing (this involves integration with an external system, but the registry's code must support it).

## Attack Surface: [Denial of Service (DoS) via Uploads](./attack_surfaces/denial_of_service__dos__via_uploads.md)

**Description:** Attackers flood the registry with large or malformed uploads, consuming resources and preventing legitimate use.
    *   **How Distribution Contributes:** The registry's upload handling code (within the API endpoints) is *directly* responsible for managing resources during the upload process.
    *   **Example:** An attacker uploads thousands of extremely large images simultaneously, exhausting storage space or network bandwidth. Or, they upload a specially crafted, deeply nested manifest that causes excessive processing time.
    *   **Impact:** Registry unavailability, disruption of CI/CD pipelines, inability to deploy applications.
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   **Developers:** Implement strict size limits on uploads (both manifests and blobs) within the registry's code. Implement timeouts and resource limits (CPU, memory) on upload operations within the registry's code. Thoroughly validate uploaded data for correctness and consistency *before* storing it, within the registry's upload handling logic.

## Attack Surface: [Unauthorized Image Access (Pulls)](./attack_surfaces/unauthorized_image_access__pulls_.md)

**Description:** Attackers gain access to private images they should not be able to retrieve.
    *   **How Distribution Contributes:** The registry's API endpoints for image pulling (`/v2/<name>/manifests/<reference>`, `/v2/<name>/blobs/<digest>`) are the *direct* mechanism for access. The registry's code is responsible for enforcing authentication and authorization.
    *   **Example:** An attacker obtains leaked credentials and pulls a sensitive image containing proprietary code or data.
    *   **Impact:** Data breaches, intellectual property theft, exposure of sensitive information.
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   **Developers:** Implement fine-grained access control (e.g., per-repository permissions, role-based access control) within the registry's authorization logic. Integrate with an external identity provider (e.g., LDAP, OAuth) – the integration points are within the registry's code.

