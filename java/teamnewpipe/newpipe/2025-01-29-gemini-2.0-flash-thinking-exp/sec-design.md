# BUSINESS POSTURE

- Business priorities and goals:
  - Provide a privacy-focused YouTube experience for Android users.
  - Offer a lightweight and efficient alternative to the official YouTube app.
  - Enable users to access YouTube content without Google tracking and advertisements.
  - Support open-source principles and community contributions.
- Business risks:
  - Risk of disruption due to changes in YouTube's API or terms of service.
  - Risk of negative user perception if privacy features are not effectively implemented or communicated.
  - Risk of legal challenges related to accessing and presenting YouTube content.
  - Risk of community burnout and lack of contributions impacting project maintenance and development.

# SECURITY POSTURE

- Existing security controls:
  - security control: Open source code, publicly available on GitHub (https://github.com/teamnewpipe/newpipe).
  - security control: Reliance on Android operating system security features.
  - security control: Use of HTTPS for communication with YouTube and other services.
- Accepted risks:
  - accepted risk: Potential vulnerabilities in open-source dependencies.
  - accepted risk: Risk associated with reverse engineering and unofficial use of YouTube's API.
  - accepted risk: Limited resources for dedicated security testing and audits.
- Recommended security controls:
  - security control: Implement automated static application security testing (SAST) in the CI/CD pipeline.
  - security control: Implement dependency scanning to identify and manage vulnerable dependencies.
  - security control: Conduct regular security code reviews, especially for critical components.
  - security control: Establish a process for reporting and handling security vulnerabilities.
- Security requirements:
  - Authentication:
    - Not applicable, NewPipe is designed for anonymous access to YouTube content.
  - Authorization:
    - The application needs authorization to access YouTube content, implicitly granted by YouTube's public API (unofficial usage).
    - User authorization within the application is limited to managing subscriptions and playlists, which are stored locally on the device.
  - Input validation:
    - Implement robust input validation for user inputs such as search queries, URLs, and settings.
    - Validate data received from YouTube API to prevent unexpected data formats or malicious content injection.
  - Cryptography:
    - Enforce HTTPS for all network communication to protect data in transit.
    - Consider encrypting sensitive data stored locally, such as user preferences or downloaded content, if deemed necessary.

# DESIGN

- C4 CONTEXT
  ```mermaid
  flowchart LR
    subgraph "YouTube Platform"
      YOUTUBE("YouTube")
    end
    subgraph "Android Device"
      NEWPIPE("NewPipe App")
    end
    USER("User")

    USER --> NEWPIPE: Uses
    NEWPIPE --> YOUTUBE: Accesses content via API
    NEWPIPE --> ANDROID_OS("Android OS"): Runs on
    USER --> ANDROID_OS: Interacts with

    style NEWPIPE fill:#f9f,stroke:#333,stroke-width:2px
    style YOUTUBE fill:#ccf,stroke:#333,stroke-width:2px
    style USER fill:#fff,stroke:#333,stroke-width:2px
    style ANDROID_OS fill:#eee,stroke:#333,stroke-width:2px
  ```

  - Elements of context diagram:
    - - Name: User
      - Type: Person
      - Description: An individual who uses the NewPipe application to access YouTube content.
      - Responsibilities: Interacts with the NewPipe application to search, watch, and download videos.
      - Security controls: User is responsible for the security of their Android device.
    - - Name: NewPipe App
      - Type: Software System
      - Description: A lightweight, privacy-focused Android application for accessing YouTube content without official YouTube API or Google services.
      - Responsibilities:
        - Provide a user interface for browsing and searching YouTube content.
        - Fetch video and metadata from YouTube servers (unofficially).
        - Play videos and audio.
        - Allow users to download videos and audio.
        - Manage user preferences and local data.
      - Security controls:
        - security control: Input validation on user inputs and API responses.
        - security control: HTTPS for network communication.
        - security control: Android OS security sandbox.
    - - Name: YouTube
      - Type: Software System
      - Description: Google's video sharing platform, providing video content and APIs (unofficial usage by NewPipe).
      - Responsibilities:
        - Host and serve video content.
        - Provide metadata and API endpoints for accessing content information.
        - Manage user accounts and content creators (not directly relevant to NewPipe).
      - Security controls:
        - security control: YouTube's own infrastructure and application security measures.
        - security control: Rate limiting and API usage policies (unofficial usage might bypass some).
    - - Name: Android OS
      - Type: Technology
      - Description: The Android operating system on which the NewPipe application runs.
      - Responsibilities:
        - Provide a secure environment for running applications.
        - Manage application permissions and access to device resources.
        - Enforce security policies and updates.
      - Security controls:
        - security control: Android security sandbox for applications.
        - security control: Permission system to control access to device features.
        - security control: Regular security updates provided by Google and device manufacturers.

- C4 CONTAINER
  ```mermaid
  flowchart LR
    subgraph "Android Device"
      subgraph "NewPipe App Container"
        ANDROID_APP("Android Application")
        LOCAL_STORAGE("Local Storage")
      end
    end
    YOUTUBE("YouTube API (Unofficial)")

    ANDROID_APP --> YOUTUBE: Uses HTTPS to fetch data
    ANDROID_APP --> LOCAL_STORAGE: Stores user data, downloads

    style ANDROID_APP fill:#f9f,stroke:#333,stroke-width:2px
    style LOCAL_STORAGE fill:#eee,stroke:#333,stroke-width:2px
    style YOUTUBE fill:#ccf,stroke:#333,stroke-width:2px
  ```

  - Elements of container diagram:
    - - Name: Android Application
      - Type: Application
      - Description: The main NewPipe Android application, written in Java/Kotlin, responsible for the application logic, user interface, and interaction with YouTube.
      - Responsibilities:
        - Handle user requests and navigation.
        - Implement application features like video playback, downloading, subscriptions.
        - Communicate with YouTube API (unofficially) to fetch data.
        - Manage local data storage.
      - Security controls:
        - security control: Input validation within the application code.
        - security control: Implementation of security best practices in code (e.g., secure coding guidelines).
        - security control: Application signing and distribution through app stores (Google Play Store, F-Droid).
    - - Name: Local Storage
      - Type: Data Store
      - Description: Local storage on the Android device used by the NewPipe application to store user preferences, downloaded videos, and potentially cached data.
      - Responsibilities:
        - Persist user settings and application state.
        - Store downloaded video and audio files.
        - Cache data to improve performance (e.g., thumbnails, search results).
      - Security controls:
        - security control: Android OS file system permissions to restrict access to application data.
        - security control: Consider encryption for sensitive data stored locally (optional, depending on sensitivity assessment).
        - security control: Regular cleanup of temporary files and cached data.
    - - Name: YouTube API (Unofficial)
      - Type: External System
      - Description: The set of undocumented APIs and web interfaces of YouTube that NewPipe uses to access content and metadata.
      - Responsibilities:
        - Provide access to YouTube video content, metadata, and search functionalities.
        - Enforce usage limits and potentially change API structure without notice.
      - Security controls:
        - security control: YouTube's own security measures for their APIs and infrastructure.
        - security control: NewPipe needs to adapt to changes in the unofficial API to maintain functionality.

- DEPLOYMENT
  ```mermaid
  flowchart LR
    subgraph "User Android Device"
      ANDROID_DEVICE("Android Device")
      NEWPIPE_INSTANCE("NewPipe Instance")
      ANDROID_OS_INSTANCE("Android OS Instance")
    end
    APP_STORE("App Store (F-Droid, etc.)")

    NEWPIPE_INSTANCE -- Runs on --> ANDROID_OS_INSTANCE
    ANDROID_OS_INSTANCE -- Runs on --> ANDROID_DEVICE
    APP_STORE -- Distributes --> NEWPIPE_INSTANCE

    style NEWPIPE_INSTANCE fill:#f9f,stroke:#333,stroke-width:2px
    style ANDROID_OS_INSTANCE fill:#eee,stroke:#333,stroke-width:2px
    style ANDROID_DEVICE fill:#ddd,stroke:#333,stroke-width:2px
    style APP_STORE fill:#ccf,stroke:#333,stroke-width:2px
  ```

  - Elements of deployment diagram:
    - - Name: Android Device
      - Type: Physical Device
      - Description: A user's physical Android mobile device or tablet.
      - Responsibilities:
        - Provide hardware resources for running the Android OS and applications.
        - Connect to networks (Wi-Fi, mobile data).
        - Store user data and applications.
      - Security controls:
        - security control: Device lock and authentication mechanisms (PIN, password, biometrics).
        - security control: Device encryption.
        - security control: User responsibility for device security and updates.
    - - Name: Android OS Instance
      - Type: Operating System Instance
      - Description: An instance of the Android operating system running on the user's device.
      - Responsibilities:
        - Manage system resources and application execution.
        - Enforce security policies and permissions.
        - Provide APIs and services to applications.
      - Security controls:
        - security control: Android security sandbox.
        - security control: Permission management.
        - security control: Regular security updates.
    - - Name: NewPipe Instance
      - Type: Software Instance
      - Description: A running instance of the NewPipe application on the user's Android device.
      - Responsibilities:
        - Execute application code and provide user functionality.
        - Access device resources and network.
        - Store and manage local application data.
      - Security controls:
        - security control: Application-level security controls (input validation, secure coding).
        - security control: Reliance on Android OS security features.
    - - Name: App Store (F-Droid, etc.)
      - Type: Distribution Platform
      - Description: Application distribution platforms like F-Droid (and potentially others) used to distribute the NewPipe application to users.
      - Responsibilities:
        - Host and distribute the NewPipe application package (APK).
        - Provide a platform for users to discover and install applications.
        - (F-Droid) Verify application builds and source code.
      - Security controls:
        - security control: (F-Droid) Build reproducibility and source code verification.
        - security control: App store security scanning (varies by store).
        - security control: HTTPS for download and distribution.

- BUILD
  ```mermaid
  flowchart LR
    DEVELOPER("Developer") --> CODE_REPO("Code Repository (GitHub)");
    CODE_REPO --> BUILD_SYSTEM("Build System (Gradle/CI)");
    BUILD_SYSTEM --> SECURITY_CHECKS("Security Checks (SAST, Dependency Scan)");
    SECURITY_CHECKS --> BUILD_ARTIFACT("Build Artifact (APK)");

    style DEVELOPER fill:#fff,stroke:#333,stroke-width:2px
    style CODE_REPO fill:#ccf,stroke:#333,stroke-width:2px
    style BUILD_SYSTEM fill:#eee,stroke:#333,stroke-width:2px
    style SECURITY_CHECKS fill:#eee,stroke:#333,stroke-width:2px
    style BUILD_ARTIFACT fill:#f9f,stroke:#333,stroke-width:2px
  ```

  - Elements of build diagram:
    - - Name: Developer
      - Type: Person
      - Description: Software developers contributing code to the NewPipe project.
      - Responsibilities:
        - Write and maintain the application code.
        - Commit code changes to the code repository.
        - Participate in code reviews.
      - Security controls:
        - security control: Secure coding practices training.
        - security control: Code review process to identify potential vulnerabilities.
        - security control: Access control to the code repository.
    - - Name: Code Repository (GitHub)
      - Type: Code Repository
      - Description: GitHub repository (https://github.com/teamnewpipe/newpipe) hosting the source code of the NewPipe project.
      - Responsibilities:
        - Store and version control the source code.
        - Manage code contributions and pull requests.
        - Trigger build processes (via CI/CD).
      - Security controls:
        - security control: Access control and authentication for repository access.
        - security control: Branch protection and code review requirements.
        - security control: Audit logs of repository activities.
    - - Name: Build System (Gradle/CI)
      - Type: Build Automation System
      - Description: Automated build system using Gradle and potentially a CI/CD platform (like GitHub Actions or Jenkins) to compile, build, and package the Android application.
      - Responsibilities:
        - Automate the build process.
        - Compile source code, manage dependencies, and create APK packages.
        - Run automated tests.
        - Potentially perform security checks.
      - Security controls:
        - security control: Secure configuration of the build environment.
        - security control: Access control to the build system and build artifacts.
        - security control: Use of trusted build tools and dependencies.
    - - Name: Security Checks (SAST, Dependency Scan)
      - Type: Security Tooling
      - Description: Integrated security tools within the build pipeline to perform static application security testing (SAST) and dependency scanning.
      - Responsibilities:
        - Automatically scan the codebase for potential security vulnerabilities.
        - Identify vulnerable dependencies.
        - Generate reports on security findings.
      - Security controls:
        - security control: Configuration and maintenance of security scanning tools.
        - security control: Review and remediation of identified security vulnerabilities.
        - security control: Integration of security checks into the build pipeline to prevent vulnerable code from being released.
    - - Name: Build Artifact (APK)
      - Type: Software Artifact
      - Description: The final Android application package (APK) produced by the build process, ready for distribution.
      - Responsibilities:
        - Contain the compiled application code and resources.
        - Be signed with a developer key for distribution.
      - Security controls:
        - security control: Application signing to ensure integrity and authenticity.
        - security control: Secure storage and distribution of the APK package.
        - security control: Provenance tracking of the build artifact back to the source code.

# RISK ASSESSMENT

- Critical business processes:
  - Providing access to YouTube content in a privacy-respecting manner.
  - Ensuring core functionalities like video playback, search, and downloads are available and reliable.
- Data we are trying to protect:
  - User preferences and settings (low sensitivity).
  - Downloaded video and audio files (medium sensitivity, could contain personal content).
  - Application code and build artifacts (medium sensitivity, integrity and availability are important).
- Data sensitivity:
  - Low to Medium. User preferences are low sensitivity. Downloaded content can be medium sensitivity depending on what user downloads. Application code and build artifacts are medium sensitivity as compromise can lead to wider impact.

# QUESTIONS & ASSUMPTIONS

- Questions:
  - Are there any specific regulatory compliance requirements for the NewPipe project (e.g., GDPR, CCPA)?
  - What is the target audience's risk tolerance regarding privacy and security?
  - Are there any plans to monetize the application, and if so, how might that impact security considerations?
  - Are there any specific deployment environments beyond standard Android devices to consider (e.g., Android TV, emulators)?
- Assumptions:
  - The primary goal is to provide a privacy-focused YouTube experience.
  - The project operates as a community-driven open-source project with limited resources.
  - Deployment is primarily through app stores like F-Droid and potentially others.
  - The application does not handle sensitive user credentials or personal identifiable information beyond user preferences and downloaded content.
  - The project relies on unofficial YouTube APIs, which are subject to change and potential disruption.