# Attack Tree Analysis for jellyfin/jellyfin

Objective: Gain Unauthorized Access/Control [!]

## Attack Tree Visualization

[Attacker's Goal: Gain Unauthorized Access/Control] [!]
    |
    |---------------------------------------------------------------------------------
    |													   |
    [Sub-Goal 1: Access Media Content]								   [Sub-Goal 3: Gain Admin Control] [!]
    |													   |
    |-------------------------												   |---------------------------------
    |        |        |													   |                |
    [1A]     [1B]     [1D]													   [3A]             [3B]
    Direct   Vuln in  Exploit													   Weak/Default    Vuln in
    Stream   Media    Transcoding													   Admin           Plugin/
    Access   Library															   Credentials [!]  Dependency
             (Path															   |				   |
             Traversal,															   |				   |
             etc.) [!]															   |				   |
    /        \															   |				   |
    [1A1]      |																   [3A1]           [3B1]
    Unauth     |																   Brute-Force     Known Vuln
    API        |																   Attack [!]	  in Plugin X [!]
    Call [!]   |
               |
               [1C1]
               FFmpeg
               Vuln [!]
               (e.g.,
               CVE-XXXX-YYYY)

## Attack Tree Path: [Media Access via FFmpeg](./attack_tree_paths/media_access_via_ffmpeg.md)

[Attacker's Goal] ---> [Sub-Goal 1] ---> [1D] ---> [1C1] (FFmpeg Vuln)

## Attack Tree Path: [Media Access via Unauthenticated API](./attack_tree_paths/media_access_via_unauthenticated_api.md)

[Attacker's Goal] ---> [Sub-Goal 1] ---> [1A] ---> [1A1] (Unauth API Call)

## Attack Tree Path: [Admin Control via Weak Credentials](./attack_tree_paths/admin_control_via_weak_credentials.md)

[Attacker's Goal] ---> [Sub-Goal 3] ---> [3A] ---> [3A1] (Brute-Force)

## Attack Tree Path: [Admin Control/RCE via Plugin](./attack_tree_paths/admin_controlrce_via_plugin.md)

[Attacker's Goal] ---> [Sub-Goal 3] ---> [3B] ---> [3B1] (Known Vuln in Plugin)

## Attack Tree Path: [Media Access via Path Traversal](./attack_tree_paths/media_access_via_path_traversal.md)

[Attacker's Goal] ---> [Sub-Goal 1] ---> [1B] (Path Traversal)

