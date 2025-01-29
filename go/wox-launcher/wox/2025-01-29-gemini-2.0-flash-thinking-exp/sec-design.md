# BUSINESS POSTURE

- Business priorities and goals:
  - The primary goal of the Wox launcher project is to provide a fast, efficient, and extensible launcher application for Windows and macOS operating systems.
  - Key priorities include user experience, performance, stability, and a rich plugin ecosystem to enhance functionality.
  - As an open-source project, community growth and contribution are also important goals.
- Business risks:
  - Reputation damage due to security vulnerabilities in the core application or plugins.
  - Loss of user trust if the application is perceived as insecure or unreliable.
  - Decreased community engagement and contribution if security concerns are not addressed.
  - Potential for malicious plugins to harm users' systems or data.

# SECURITY POSTURE

- Existing security controls:
  - security control: Open-source codebase hosted on GitHub, providing transparency and allowing community review. (Implemented: GitHub Repository)
  - security control: Code review process through pull requests on GitHub, although the depth and security focus of these reviews are not explicitly defined. (Implemented: GitHub Pull Requests)
- Accepted risks:
  - accepted risk: Potential vulnerabilities may exist due to reliance on community contributions and volunteer effort for security maintenance.
  - accepted risk: Risk of vulnerabilities in third-party plugins developed by the community, as plugin security review process is not explicitly defined.
- Recommended security controls:
  - recommended security control: Implement automated Static Application Security Testing (SAST) tools in the CI/CD pipeline to identify potential code vulnerabilities.
  - recommended security control: Implement Dependency Vulnerability Scanning to identify and manage vulnerabilities in third-party libraries used by the project.
  - recommended security control: Establish a clear process for security vulnerability reporting and response.
  - recommended security control: Define and publish security guidelines for plugin developers to minimize security risks from plugins.
  - recommended security control: Consider implementing a plugin review process, potentially community-driven, to identify and mitigate security risks in popular plugins.
- Security requirements:
  - Authentication:
    - Not directly applicable to the core launcher application itself, as it is primarily a local desktop tool.
    - Plugins that interact with external services or require user accounts may need to implement authentication mechanisms. Security requirements for plugin authentication should be clearly defined.
  - Authorization:
    - The launcher needs to manage permissions for plugins to access system resources and user data. A plugin permission model should be in place to control what plugins can access.
    - Authorization is needed to control access to sensitive settings and configurations within the launcher application itself.
  - Input validation:
    - All user inputs, including search queries and plugin inputs, must be properly validated to prevent injection attacks (e.g., command injection, script injection).
    - Plugin inputs and outputs should be validated to ensure data integrity and prevent unexpected behavior.
  - Cryptography:
    - If the launcher or plugins store sensitive data locally (e.g., API keys, credentials), appropriate encryption mechanisms should be used to protect this data at rest.
    - Secure communication protocols (HTTPS) should be used for any network communication performed by the launcher or plugins.

# DESIGN

- C4 CONTEXT
  ```mermaid
  flowchart LR
    subgraph Internet
      WebSearchEngines("Web Search Engines")
    end
    User("User")
    Wox("Wox Launcher")
    OperatingSystem("Operating System")
    Plugins("Plugins")
    LocalApplications("Local Applications")

    User --> Wox
    Wox --> OperatingSystem
    Wox --> Plugins
    Wox --> LocalApplications
    Wox --> WebSearchEngines
    Plugins --> OperatingSystem
    Plugins --> LocalApplications
  ```

  - C4 CONTEXT Elements:
    - - Name: User
      - Type: Person
      - Description: End-user interacting with the Wox launcher application to launch applications, search the web, and perform other tasks.
      - Responsibilities: Provides input to the Wox launcher through search queries and commands. Receives output from the launcher, such as application launches and search results.
      - Security controls: User is responsible for the security of their own system and the plugins they choose to install.
    - - Name: Wox Launcher
      - Type: Software System
      - Description: The Wox launcher application itself, providing the core functionality of application launching, web searching, and plugin management.
      - Responsibilities: Receives user input, processes commands, interacts with the operating system, manages plugins, and displays results to the user.
      - Security controls: Input validation, plugin permission management, secure configuration storage, update mechanism.
    - - Name: Operating System
      - Type: Software System
      - Description: The underlying operating system (Windows or macOS) on which Wox is running. Provides system resources and APIs for Wox and plugins to interact with.
      - Responsibilities: Manages system resources, executes applications, provides APIs for file system access, process management, and other system functionalities.
      - Security controls: Operating system security controls, such as user permissions, access control lists, and system updates.
    - - Name: Plugins
      - Type: Software System
      - Description: Extensible plugins that extend the functionality of Wox, providing features like custom commands, integrations with external services, and enhanced search capabilities.
      - Responsibilities: Provide additional features and functionalities to Wox. Interact with the operating system, local applications, and external services based on their purpose.
      - Security controls: Plugin permission model, input validation within plugins, potentially plugin sandboxing (depending on implementation).
    - - Name: Local Applications
      - Type: Software System
      - Description: Applications installed on the user's local system that Wox can launch and interact with.
      - Responsibilities: Provide functionalities and services to the user. Launched and managed by the operating system and Wox.
      - Security controls: Application-level security controls, operating system access controls.
    - - Name: Web Search Engines
      - Type: External System
      - Description: External web search engines (e.g., Google, Bing, DuckDuckGo) that Wox can use to perform web searches based on user queries.
      - Responsibilities: Provide web search results based on queries received from Wox.
      - Security controls: HTTPS for communication, reliance on the security of external search engine services.

- C4 CONTAINER
  ```mermaid
  flowchart LR
    subgraph UserDesktop [User's Desktop]
      WoxApp("Wox Application")
      PluginsContainer("Plugins Container")
      ConfigFile("Configuration File")
    end
    OperatingSystemContainer("Operating System APIs")
    WebSearchEnginesContainer("Web Search Engines APIs")
    LocalAppsContainer("Local Applications")

    User -- Uses --> WoxApp
    WoxApp -- Uses --> PluginsContainer
    WoxApp -- Reads/Writes --> ConfigFile
    WoxApp -- Uses --> OperatingSystemContainer
    WoxApp -- Uses --> WebSearchEnginesContainer
    WoxApp -- Launches --> LocalAppsContainer
    PluginsContainer -- Uses --> OperatingSystemContainer
    PluginsContainer -- Launches --> LocalAppsContainer
  ```

  - C4 CONTAINER Elements:
    - - Name: Wox Application
      - Type: Desktop Application
      - Description: The main executable of the Wox launcher, responsible for the user interface, core launcher logic, plugin management, and communication with other containers.
      - Responsibilities: User input handling, command parsing, plugin loading and management, search execution, result display, configuration management.
      - Security controls: Input validation, plugin permission management, secure configuration storage, update mechanism, secure inter-process communication with plugins container.
    - - Name: Plugins Container
      - Type: Dynamically Loaded Modules
      - Description: A container for dynamically loaded plugins, allowing extension of Wox functionality. Plugins run within this container, potentially in the same process or a separate process with inter-process communication.
      - Responsibilities: Hosting and executing plugins, providing APIs for plugins to interact with Wox and the operating system, managing plugin lifecycle.
      - Security controls: Plugin permission model, input validation within plugins, potentially plugin sandboxing or process isolation, secure communication with Wox Application.
    - - Name: Configuration File
      - Type: Data Store (File)
      - Description: Stores Wox application settings, user preferences, plugin configurations, and potentially cached data.
      - Responsibilities: Persistent storage of application and user settings.
      - Security controls: File system permissions to restrict access, encryption of sensitive data within the configuration file if necessary.
    - - Name: Operating System APIs
      - Type: System Interface
      - Description: APIs provided by the operating system (Windows or macOS) that Wox and plugins use to interact with the system, such as file system access, process management, and UI rendering.
      - Responsibilities: Providing system functionalities to Wox and plugins.
      - Security controls: Operating system security controls, API access restrictions.
    - - Name: Web Search Engines APIs
      - Type: External API
      - Description: APIs of external web search engines used by Wox to perform web searches.
      - Responsibilities: Providing web search results via API.
      - Security controls: HTTPS for communication, API authentication (if required by search engine), rate limiting.
    - - Name: Local Applications
      - Type: Executable Programs
      - Description: Applications installed on the user's system that Wox can launch.
      - Responsibilities: Provide functionalities to the user when launched by Wox.
      - Security controls: Application-level security controls, operating system access controls.

- DEPLOYMENT
  - Deployment Architecture Options:
    - Option 1: Standalone Desktop Application - Users download and install the Wox application directly onto their Windows or macOS machines. This is the most likely current deployment model.
    - Option 2: Package Manager Distribution - Distribute Wox through package managers (e.g., Chocolatey, Homebrew) for easier installation and updates.
  - Detailed Deployment Architecture (Option 1 - Standalone Desktop Application):

  ```mermaid
  flowchart LR
    subgraph UserEnvironment [User's Local Machine]
      UserDevice("User Device (Windows/macOS)")
      WoxInstallation("Wox Application Installation Directory")
    end
    DistributionServer("Distribution Server (GitHub Releases)")

    User -- Downloads Installer --> DistributionServer
    User -- Executes Installer --> UserDevice
    UserDevice -- Installs Wox --> WoxInstallation
    WoxInstallation -- Runs on --> UserDevice
  ```

  - DEPLOYMENT Elements:
    - - Name: User Device (Windows/macOS)
      - Type: Physical Device
      - Description: The user's personal computer running either Windows or macOS operating system.
      - Responsibilities: Provides the environment for running the Wox application.
      - Security controls: User device security controls, operating system security features, endpoint security software.
    - - Name: Wox Application Installation Directory
      - Type: File System Directory
      - Description: The directory on the user's device where the Wox application files are installed.
      - Responsibilities: Contains all necessary files for running the Wox application, including executables, libraries, and configuration files.
      - Security controls: File system permissions to protect application files from unauthorized modification.
    - - Name: Distribution Server (GitHub Releases)
      - Type: Web Server
      - Description: Server hosting the Wox application installers and update files, likely GitHub Releases in this case.
      - Responsibilities: Provides installers and updates for users to download.
      - Security controls: HTTPS for secure download, server security controls on GitHub infrastructure.

- BUILD
  - Build Process:
    - Developers write code and commit to the GitHub repository.
    - A CI/CD system (likely GitHub Actions) is triggered on code changes.
    - The CI/CD pipeline performs the following steps:
      - Code checkout.
      - Dependency installation.
      - Compilation and building of the Wox application for Windows and macOS.
      - Running automated tests (unit tests, integration tests).
      - Running security checks (SAST, dependency scanning - recommended).
      - Packaging the application into installers (e.g., .exe, .dmg).
      - Publishing build artifacts (installers) to GitHub Releases.

  ```mermaid
  flowchart LR
    Developer("Developer")
    GitHubRepo("GitHub Repository")
    CI_CD("CI/CD System (GitHub Actions)")
    BuildArtifacts("Build Artifacts (Installers)")
    GitHubReleases("GitHub Releases")

    Developer -- Push Code --> GitHubRepo
    GitHubRepo -- Triggers --> CI_CD
    CI_CD -- Builds & Tests --> BuildArtifacts
    BuildArtifacts -- Uploads --> GitHubReleases
  ```

  - BUILD Elements:
    - - Name: Developer
      - Type: Person
      - Description: Software developers contributing code to the Wox project.
      - Responsibilities: Writing code, fixing bugs, implementing features, and committing changes to the repository.
      - Security controls: Secure development practices, code review, access control to the GitHub repository.
    - - Name: GitHub Repository
      - Type: Code Repository
      - Description: The GitHub repository hosting the Wox project source code.
      - Responsibilities: Version control, code storage, collaboration platform.
      - Security controls: Access control, branch protection, audit logs, vulnerability scanning by GitHub.
    - - Name: CI/CD System (GitHub Actions)
      - Type: Automation System
      - Description: Continuous Integration and Continuous Delivery system used to automate the build, test, and release process.
      - Responsibilities: Automated build, testing, security checks, packaging, and deployment.
      - Security controls: Secure pipeline configuration, access control to CI/CD workflows, secrets management, integration with security scanning tools.
    - - Name: Build Artifacts (Installers)
      - Type: Software Packages
      - Description: Compiled and packaged installers for Wox application (e.g., .exe for Windows, .dmg for macOS).
      - Responsibilities: Distributable packages of the Wox application.
      - Security controls: Code signing of installers to ensure integrity and authenticity.
    - - Name: GitHub Releases
      - Type: File Hosting Service
      - Description: GitHub Releases section used to host and distribute Wox application installers.
      - Responsibilities: Distribution point for Wox application installers.
      - Security controls: HTTPS for download, integrity checks (e.g., checksums) for downloaded files.

# RISK ASSESSMENT

- Critical business process:
  - Maintaining user trust and a positive reputation for the Wox launcher.
  - Ensuring the application is safe and reliable for users to use daily.
  - Supporting a healthy and active plugin ecosystem.
- Data we are trying to protect and their sensitivity:
  - User search queries: Sensitivity - Low to Medium. While generally not highly sensitive, search queries can sometimes contain personal or private information. These are processed locally and not typically transmitted or stored by Wox itself, but plugins might handle them.
  - User configuration and settings: Sensitivity - Low. User preferences and application settings. Loss or corruption could cause inconvenience, but not typically a high security risk.
  - Plugin configurations and data: Sensitivity - Low to Medium. Depends on the plugin. Some plugins might store API keys or access tokens. These should be protected.
  - Application code and build artifacts: Sensitivity - Medium. Protecting the integrity and authenticity of the application code and build artifacts is important to prevent supply chain attacks and malicious modifications.

# QUESTIONS & ASSUMPTIONS

- Questions:
  - What is the current process for managing and reviewing plugins? Is there any form of plugin store or curated list?
  - Are there any existing security guidelines for plugin developers?
  - How are user settings and plugin data currently stored? Is any sensitive data encrypted at rest?
  - What automated security testing tools are currently used in the CI/CD pipeline, if any?
  - Is there a defined process for handling security vulnerability reports?
- Assumptions:
  - The project is primarily community-driven and relies on volunteer contributions.
  - The main distribution channel is GitHub Releases.
  - There is no formal security team dedicated to the project, and security is addressed by community members and maintainers.
  - The application is designed to be lightweight and performant, with a focus on user experience.
  - Plugins are a key feature for extending functionality and are developed by the community.