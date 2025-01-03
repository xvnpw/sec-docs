
# Project Design Document: Sway Window Manager

**Version:** 1.1
**Date:** October 26, 2023
**Author:** AI Architecture Expert

## 1. Introduction

This document provides a refined and more detailed design overview of the Sway window manager, building upon the previous version. Sway is a tiling Wayland compositor intended as a direct replacement for the i3 window manager. The primary goal of this document is to offer a clear and comprehensive understanding of Sway's architecture, components, and interactions, specifically tailored for subsequent threat modeling activities. We will delve deeper into the core functionalities and security-relevant aspects of Sway.

### 1.1. Project Overview

Sway aims to provide a seamless transition for i3 users to the modern Wayland protocol, offering a familiar configuration syntax and user experience. By leveraging Wayland, Sway benefits from its inherent security and architectural advantages compared to X11. The overarching goal of Sway is to deliver a stable, performant, and secure tiling window management solution for Linux and other Unix-like operating systems.

### 1.2. Goals of this Document

*   Clearly and comprehensively define the architecture and components of the Sway window manager, with a focus on security implications.
*   Thoroughly describe the interactions between different components, external entities, and the underlying system.
*   Precisely identify key data flows within the system, highlighting potential points of vulnerability.
*   Provide a robust and detailed foundation for identifying potential security vulnerabilities through comprehensive threat modeling.

### 1.3. Scope

This document focuses on the core compositor functionality of Sway, providing a deeper level of detail than the previous version. It includes:

*   The main Sway process and its internal modules, with a more granular breakdown.
*   Detailed interaction with the Wayland compositor (wlroots), including relevant protocols.
*   In-depth analysis of input event handling and processing.
*   Comprehensive management of client windows, including lifecycle and properties.
*   Detailed examination of configuration parsing and application, including security considerations.
*   Thorough description of Inter-Process Communication (IPC) mechanisms, including the protocol used.

This document excludes:

*   Extremely low-level implementation specifics of individual functions or libraries, unless directly relevant to security.
*   The complete intricacies of the Wayland protocol itself, focusing on Sway's usage and interactions.
*   Specific internal workings of client applications running under Sway.

## 2. High-Level Architecture

```mermaid
graph LR
    subgraph "User"
        U["User"]
    end
    subgraph "Sway Compositor"
        direction LR
        IH["Input Handling"]
        WM["Window Management"]
        RE["Rendering Engine"]
        CFG["Configuration Manager"]
        IPCM["IPC Manager"]
    end
    subgraph "Wayland Compositor (wlroots)"
        WLC["wlroots Library"]
    end
    subgraph "Wayland Clients"
        C1["Client App 1"]
        CN["Client App N"]
    end
    subgraph "System Resources"
        KRNL["Kernel / Drivers"]
        FILS["File System"]
    end

    U --> IH
    IH --> WM
    WM --> RE
    RE --> WLC
    WLC --> KRNL
    KRNL --> "Display Hardware"

    WM --> IPCM
    IPCM --> C1
    IPCM --> CN

    CFG --> "Sway Compositor"

    C1 --> WLC
    CN --> WLC

    style U fill:#f9f,stroke:#333,stroke-width:2px
    style IH fill:#ccf,stroke:#333,stroke-width:2px
    style WM fill:#ccf,stroke:#333,stroke-width:2px
    style RE fill:#ccf,stroke:#333,stroke-width:2px
    style CFG fill:#ccf,stroke:#333,stroke-width:2px
    style IPCM fill:#ccf,stroke:#333,stroke-width:2px
    style WLC fill:#aaf,stroke:#333,stroke-width:2px
    style C1 fill:#eee,stroke:#333,stroke-width:2px
    style CN fill:#eee,stroke:#333,stroke-width:2px
    style KRNL fill:#ddd,stroke:#333,stroke-width:2px
    style FILS fill:#ddd,stroke:#333,stroke-width:2px
```

### 2.1. Actors and Components

*   **User:** Interacts with the system through various input devices (keyboard, mouse, touchpads, etc.).
*   **Sway Compositor:** The central process responsible for managing the Wayland session, handling input, arranging and drawing windows. It comprises several key modules:
    *   **Input Handling (IH):**  Receives, processes, and dispatches events from input devices. This includes handling keyboard layouts, input methods, and translating raw events into Wayland events.
    *   **Window Management (WM):** Manages the state, properties, and layout of client windows. This involves implementing tiling algorithms, managing workspaces and outputs, and applying user-defined rules.
    *   **Rendering Engine (RE):**  Handles the composition and drawing of window contents to the display, leveraging the capabilities of `wlroots`. This includes managing damage tracking, redraws, and potentially supporting various rendering backends (e.g., OpenGL, Vulkan via `wlroots`).
    *   **Configuration Manager (CFG):** Parses and applies the user's configuration file, setting up keybindings, window rules, output configurations, and other system behaviors. It also handles reloading the configuration.
    *   **IPC Manager (IPCM):** Provides a mechanism for external applications to communicate with Sway using a Unix socket and a defined protocol. This allows for sending commands and subscribing to events.
*   **Wayland Compositor (wlroots):** A modular Wayland compositor library that Sway utilizes. It handles the low-level details of the Wayland protocol, including managing Wayland objects, surfaces, and protocols.
*   **Wayland Clients:** Applications that run under Sway and communicate using the Wayland protocol. They render their content to Wayland surfaces and interact with the compositor for input and window management.
*   **System Resources:**  Encompasses the kernel, device drivers, and the file system where configuration files and other persistent data are stored.

### 2.2. Interactions

*   The **User** generates input events that are captured by the **Input Handling** module.
*   The **Input Handling** module interprets these events and forwards relevant information to the **Window Management** module.
*   The **Window Management** module determines how to arrange and manage windows based on user input, internal state, and configuration.
*   The **Rendering Engine** uses the **wlroots Library** to composite and draw the final output to the display hardware, driven by the window layout determined by the **Window Management** module.
*   **Wayland Clients** communicate with the **wlroots Library** to create surfaces, draw their content, and receive input events.
*   The **Configuration Manager** reads and parses configuration files from the **File System** at startup and when reloaded.
*   External applications interact with the **Sway Compositor** through the **IPC Manager**, sending commands and receiving events.

## 3. Detailed Design

### 3.1. Sway Compositor Modules (Detailed)

*   **Input Handling (IH):**
    *   Receives raw input events from the kernel via `libinput` (used by `wlroots`).
    *   Translates raw events into Wayland input events (e.g., `wl_keyboard`, `wl_pointer`).
    *   Manages keyboard layouts using `libxkbcommon`.
    *   Handles input methods via the Input Method Protocol.
    *   Matches input events against configured keyboard shortcuts and commands.
    *   Dispatches input events to the focused client window or handles them internally (e.g., for system commands).
    *   Security Consideration: Improper handling or validation of input events could lead to vulnerabilities like input injection or denial of service.
*   **Window Management (WM):**
    *   Maintains a data structure representing the state of all managed windows (position, size, stacking order, focus, etc.).
    *   Implements tiling algorithms (e.g., horizontal/vertical splitting, stacking, tabbed layouts).
    *   Manages workspaces (virtual desktops) and outputs (monitors).
    *   Handles window creation (via the Wayland protocol), destruction, and focus changes.
    *   Applies user-defined rules for window placement, behavior, and decorations.
    *   Security Consideration: Bugs in window management logic could potentially lead to clients gaining unauthorized access to other clients' surfaces or compositor resources.
*   **Rendering Engine (RE):**
    *   Utilizes the rendering abstractions provided by `wlroots` (e.g., `wlr_renderer`, `wlr_compositor`).
    *   Composites the final output by combining the rendered surfaces of client windows and any compositor elements (e.g., borders, overlays).
    *   Handles damage tracking to efficiently redraw only the necessary parts of the screen.
    *   Supports various rendering backends through `wlroots`, typically OpenGL or Vulkan.
    *   Security Consideration: Vulnerabilities in the rendering pipeline or the underlying graphics drivers could potentially be exploited.
*   **Configuration Manager (CFG):**
    *   Parses the Sway configuration file (typically `~/.config/sway/config`) using a custom parser.
    *   Applies settings for keybindings, window rules (using criteria like app_id, window class, etc.), output configuration (resolution, refresh rate, etc.), input device settings, and more.
    *   Monitors the configuration file for changes using file system notifications (e.g., `inotify`) and reloads the configuration when changes are detected.
    *   Security Consideration: Insecure parsing of the configuration file could potentially lead to vulnerabilities if a malicious user can inject crafted content. Improper handling of file permissions on the configuration file is a major security concern.
*   **IPC Manager (IPCM):**
    *   Listens for connections on a Unix domain socket (typically `/run/user/$UID/sway-ipc.$DISPLAY.sock`).
    *   Implements a JSON-based protocol for communication. Clients send JSON commands, and Sway responds with JSON data or events.
    *   Supports various commands for controlling Sway's behavior (e.g., `workspace`, `focus`, `exec`).
    *   Allows clients to subscribe to events (e.g., `window`, `workspace`, `shutdown`).
    *   Security Consideration: The IPC socket is a significant attack surface. Lack of proper authentication or authorization could allow any local process to control Sway. The security of the JSON parsing and command execution is also critical.

### 3.2. Data Flow (Detailed Example: Handling a Key Press)

1. **Input Event:** The user presses a key on the keyboard.
2. **Kernel/Drivers:** The kernel and input drivers detect the key press and generate a raw input event.
3. **wlroots Library:** `wlroots` receives the raw input event via `libinput`.
4. **Input Handling (Sway):** Sway's input handling module receives the `libinput` event via `wlroots`'s event handling mechanisms.
5. **Keymapping and Translation:** The input handling module uses `libxkbcommon` to determine the keysym and modifiers associated with the key press based on the current keyboard layout.
6. **Keybinding Lookup:** The input handling module searches its internal table of configured keybindings to see if the current key press matches any defined shortcuts.
7. **Command Execution (Internal):** If a keybinding matches an internal Sway command (e.g., `workspace 2`), the input handling module signals the window management module to execute the command.
8. **Wayland Event Dispatch (Client):** If the key press is intended for the currently focused client window (e.g., typing text), the input handling module creates a `wl_keyboard` event and sends it to the client via the Wayland protocol.
9. **Client Processing:** The client application receives the `wl_keyboard` event and processes it (e.g., inserting the typed character into a text field).
10. **Rendering Update (Client):** If the client's state changes due to the input, it typically requests a redraw of its surface via the Wayland protocol (e.g., by committing a buffer).
11. **Composition and Rendering (Sway):** Sway's rendering engine, using `wlroots`, composites the updated client window surface and redraws the affected region of the screen.

### 3.3. Configuration (Detailed)

*   The Sway configuration file uses a command-based syntax, similar to i3.
*   Commands can set options, define keybindings, specify window rules, configure outputs and input devices, and more.
*   The configuration parser in Sway is responsible for interpreting these commands and applying the corresponding settings.
*   Environment variables can be used within the configuration file.
*   Includes and imports of other configuration files are supported.
*   Security Consideration: The complexity of the configuration language and parser can introduce vulnerabilities if not implemented carefully. The ability to execute external commands via the `exec` command in the configuration poses a significant security risk if not properly managed.

### 3.4. Inter-Process Communication (IPC) (Detailed)

*   Sway's IPC uses a Unix domain socket for local communication.
*   The communication protocol is based on sending and receiving JSON messages.
*   Clients can send commands to Sway, such as:
    *   Workspace management: `workspace`, `move container to workspace`.
    *   Window management: `focus`, `kill`, `resize`.
    *   Configuration manipulation: `reload`.
    *   Execution of external commands: `exec`.
*   Clients can subscribe to events, such as:
    *   `window`: Notifications about window creation, destruction, focus changes, etc.
    *   `workspace`: Notifications about workspace changes.
    *   `shutdown`: Notification when Sway is about to exit.
    *   Security Consideration: The `exec` command within the IPC protocol allows arbitrary command execution, making it a critical area for security considerations. Proper authorization and validation of IPC commands are essential.

## 4. Security Considerations (Advanced)

This section expands upon the preliminary security considerations, providing more specific details relevant for threat modeling.

*   **Configuration File Security:**
    *   The configuration file (`~/.config/sway/config`) should have restrictive permissions (e.g., `0600` or `0644` for single-user systems). World-readable or writable configuration files pose a significant risk.
    *   The Sway configuration parser needs to be robust against maliciously crafted input to prevent vulnerabilities like buffer overflows or arbitrary code execution.
    *   The `exec` command within the configuration file allows execution of arbitrary shell commands with the user's privileges. This is a significant attack vector if the configuration file is compromised.
*   **IPC Security:**
    *   The Unix domain socket used for IPC typically relies on file system permissions for access control. However, this can be bypassed by processes running with the same user ID.
    *   The lack of built-in authentication or authorization mechanisms for IPC means any local process running as the same user can connect and send commands to Sway.
    *   The JSON parsing of IPC messages needs to be secure to prevent vulnerabilities.
    *   The `exec` command within the IPC protocol allows arbitrary command execution, requiring careful consideration during threat modeling.
*   **Input Handling Security:**
    *   Vulnerabilities in `libinput` or Sway's input handling logic could allow for input injection or manipulation, potentially leading to unintended actions or security breaches.
    *   Careful handling of keyboard layouts and input methods is necessary to prevent exploits.
*   **Client Isolation:**
    *   While Wayland provides better client isolation than X11, vulnerabilities in Sway or `wlroots` could still allow clients to interfere with each other or the compositor.
    *   Bugs in surface management or buffer handling could potentially lead to information leaks between clients.
*   **Dependency Security:**
    *   Sway's security posture is dependent on the security of its dependencies, particularly `wlroots`, `libinput`, and `libxkbcommon`.
    *   Regularly updating dependencies and monitoring for security vulnerabilities in these libraries is crucial.
*   **Privilege Separation:**
    *   Sway runs with the user's privileges. If vulnerabilities are present, they can be exploited to gain full user access.
    *   Exploring potential for further privilege separation within Sway's architecture could enhance security.
*   **Wayland Protocol Security:**
    *   While Wayland aims to be more secure than X11, vulnerabilities can still exist in the protocol implementation in `wlroots` or in Sway's usage of the protocol.

## 5. Technologies Used

*   **Programming Language:** C
*   **Wayland Compositor Library:** wlroots
*   **Input Handling Library:** libinput
*   **Keyboard Layout Handling:** libxkbcommon
*   **IPC:** Unix domain sockets, JSON
*   **Configuration Language:** Custom text-based format
*   **Build System:** Meson

## 6. Future Considerations

*   Exploring options for adding authentication or authorization mechanisms to the IPC protocol.
*   Investigating potential for sandboxing or further isolating client applications to limit the impact of potential vulnerabilities.
*   Continued focus on secure coding practices and thorough testing to minimize vulnerabilities.
*   Integration with security-focused desktop environment components or security modules.

This improved design document provides a more detailed and security-focused overview of the Sway window manager's architecture. The enhanced descriptions of components, data flows, and security considerations offer a stronger foundation for conducting thorough threat modeling activities.