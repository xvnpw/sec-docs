# Threat Model Analysis for tailscale/tailscale

## Threat: [Compromised Tailscale Client Leads to Lateral Movement](./threats/compromised_tailscale_client_leads_to_lateral_movement.md)

**Description:** An attacker gains control of a device running the Tailscale client application. Once compromised, the attacker can use the Tailscale connection to access other devices within the private Tailnet as if they were on the local network. They might scan for open ports, access internal services, or exfiltrate data from other connected machines *through the Tailscale-established network interface*.

**Impact:** Unauthorized access to internal resources, data breaches from other connected systems, potential for further compromise of other devices within the Tailnet *via the Tailscale network*.

**Affected Tailscale Component:** Tailscale Client application (specifically the network interface and connection management).

**Risk Severity:** High

**Mitigation Strategies:**
* Implement robust endpoint security measures (antivirus, EDR) on all devices running the Tailscale client.
* Keep operating systems and software on all Tailscale-connected devices up to date with security patches.
* Enforce strong password policies and multi-factor authentication for device logins.
* Utilize Tailscale's device authorization features and regularly review authorized devices.
* Consider network segmentation within the Tailnet using Tailscale's ACLs to limit the impact of a compromised device.

## Threat: [Rogue Device Introduction and Network Access](./threats/rogue_device_introduction_and_network_access.md)

**Description:** An attacker successfully adds an unauthorized device to the Tailnet. This could involve obtaining a valid authorization key through social engineering, insider threat, or by exploiting vulnerabilities in the *Tailscale device onboarding process*. Once added, the rogue device gains network access to all other devices on the Tailnet, potentially allowing for reconnaissance, exploitation, and data theft *through the Tailscale network*.

**Impact:** Unauthorized access to internal resources, potential for man-in-the-middle attacks within the Tailnet if not using application-level encryption, introduction of malicious software into the private network *via the Tailscale network*.

**Affected Tailscale Component:** Tailscale Client (device onboarding/authentication), Tailscale Control Plane (device management).

**Risk Severity:** High

**Mitigation Strategies:**
* Strictly control device authorization using Tailscale's features (e.g., requiring admin approval).
* Regularly review the list of authorized devices in the Tailscale admin panel.
* Implement notification mechanisms for new device authorizations.
* Educate users about the risks of sharing authorization keys and the device onboarding process.
* Consider using Tailscale's SSO integration for stricter identity management.

## Threat: [Compromise of Tailscale Node Keys](./threats/compromise_of_tailscale_node_keys.md)

**Description:** An attacker gains access to the cryptographic keys associated with a specific Tailscale node (device). This could happen through malware targeting key storage, physical access to a device, or exploiting vulnerabilities in *how Tailscale manages keys on the client*. With the compromised keys, the attacker can impersonate that device on the Tailnet, potentially intercepting traffic destined for it or acting as that device to other members of the network.

**Impact:** Ability to impersonate legitimate devices *within the Tailscale network*, potential for eavesdropping on communication within the Tailnet, unauthorized access to resources intended for the compromised node.

**Affected Tailscale Component:** Tailscale Client (key management).

**Risk Severity:** High

**Mitigation Strategies:**
* Implement strong device security measures to prevent unauthorized access and malware infections.
* Utilize secure key storage practices on the operating system level.
* Consider the implications of a key compromise in your incident response plan.
* While Tailscale handles key rotation automatically, understanding the process is important for incident response.

