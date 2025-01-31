# BUSINESS POSTURE

- Business Priorities and Goals:
  - In its active phase, Three20 aimed to accelerate and simplify iOS application development, primarily for Facebook's own iOS applications and potentially for external developers.
  - The project's goal was to provide a comprehensive library of reusable UI components, utilities, and helper classes, reducing development time and promoting code consistency across iOS projects.
  - By open-sourcing Three20, Facebook might have also aimed to foster community contributions and wider adoption, benefiting from external improvements and bug fixes.

- Most Important Business Risks:
  - Security vulnerabilities within the Three20 library could be inherited by applications using it, potentially exposing user data or application functionality to malicious actors. This risk was particularly significant for Facebook's own applications and any other high-profile apps relying on Three20.
  - Instability or bugs in the framework could lead to application crashes or unexpected behavior, negatively impacting user experience and potentially damaging the reputation of applications using Three20.
  - As an open-source project, reliance on community contributions for maintenance and security updates introduced a dependency risk. If community support waned, the project could become outdated or unmaintained, increasing security and stability risks over time.
  - Given that the project is now archived, the primary business risk is historical impact on applications that were built using Three20 and are still in use. For new projects, using an archived and unmaintained library poses significant risks.

# SECURITY POSTURE

- Existing Security Controls:
  - security control: Code Reviews - It is assumed that during active development, code changes were subject to peer review to identify potential security vulnerabilities and coding errors. Location: Facebook's internal development process and potentially community contribution guidelines.
  - security control: Static Analysis - It is possible that static analysis tools were used to scan the codebase for common security flaws and coding style violations. Location: Integrated into Facebook's development pipeline or used by individual developers.
  - security control: Unit and Integration Testing - Standard testing practices were likely employed to ensure the functionality and stability of the library, indirectly contributing to security by reducing bugs. Location: Project's test suite (if available and documented).
  - security control: Open Source Transparency - As an open-source project, the codebase was publicly accessible, allowing for community scrutiny and potential identification of security issues by external researchers. Location: GitHub repository.

- Accepted Risks:
  - accepted risk: Dependency on Open Source - Relying on an open-source library inherently involves a degree of trust in the maintainers and the community. Security vulnerabilities discovered in dependencies could impact projects using Three20.
  - accepted risk: Community Security Contributions - While community contributions can be beneficial, the quality and security rigor of external contributions can vary, potentially introducing vulnerabilities if not properly vetted.
  - accepted risk: Time to Patch Vulnerabilities - The time taken to identify, patch, and distribute fixes for security vulnerabilities in an open-source project can be longer compared to internally developed and controlled software.
  - accepted risk: Project Archival - As the project is now archived, there are no ongoing security updates or maintenance. Any existing vulnerabilities will remain unpatched, and new vulnerabilities discovered will not be addressed by the original developers or community.

- Recommended Security Controls:
  - recommended security control: Dependency Scanning - Implement automated dependency scanning to identify known vulnerabilities in third-party libraries used by Three20.
  - recommended security control: Vulnerability Scanning - Regularly scan the codebase with vulnerability scanners to detect potential security flaws.
  - recommended security control: Fuzzing - Employ fuzzing techniques to test the robustness of input handling and identify potential crash-inducing or exploitable inputs.
  - recommended security control: Security Audits - Conduct periodic security audits by external security experts to comprehensively assess the codebase for vulnerabilities. (Historically relevant during active development).
  - recommended security control: Secure Software Development Lifecycle (SSDLC) - Implement a formal SSDLC process that integrates security considerations into every stage of development, from design to deployment. (Historically relevant during active development).

- Security Requirements:
  - Authentication:
    - Not directly applicable to a UI framework. Authentication is typically handled by the applications using Three20, not by the framework itself.
  - Authorization:
    - Not directly applicable to a UI framework. Authorization logic resides within the applications using Three20.
  - Input Validation:
    - Security Requirement: Implement robust input validation for all user inputs handled by UI components within Three20 to prevent injection attacks (e.g., cross-site scripting if rendering web content, SQL injection if interacting with databases indirectly through the framework).
    - Security Requirement: Validate data received from external sources (e.g., network requests) before processing and displaying it in UI components to prevent data integrity issues and potential vulnerabilities.
  - Cryptography:
    - Security Requirement: If Three20 handles or stores sensitive data locally (e.g., caching), ensure that appropriate encryption mechanisms are used to protect data at rest.
    - Security Requirement: If Three20 facilitates network communication, ensure that secure communication protocols (e.g., HTTPS) are used to protect data in transit. (Likely responsibility of the application using Three20, but the framework should not hinder secure networking).

# DESIGN

## C4 CONTEXT

```mermaid
flowchart LR
    subgraph "Mobile User"
        U[User]
    end
    subgraph "iOS Ecosystem"
        IOS[iOS Platform]
        AppStore[App Store]
    end
    subgraph "Three20 Project"
        T20[Three20 Library]
    end
    subgraph "Developer Ecosystem"
        Dev[iOS Developers]
        Github[GitHub Repository]
        Xcode[Xcode IDE]
    end

    U --> IOS
    IOS --> AppStore
    AppStore --> "Apps using Three20"
    "Apps using Three20" --> T20
    Dev --> Xcode
    Xcode --> T20
    Dev --> Github
    Github --> T20
    T20 -- "Built with" --> Xcode
    T20 -- "Distributed via" --> Github

    linkStyle 0,1,2,3,4,5,6,7,8,9 stroke-width:2px,stroke:black;
```

- Context Diagram Elements:
  - - Name: User
    - Type: Person
    - Description: End-users who interact with iOS applications built using the Three20 library.
    - Responsibilities: Use iOS applications for various purposes.
    - Security controls: User devices and user behavior are outside the direct control of the Three20 library. Security depends on the overall application and device security posture.
  - - Name: iOS Platform
    - Type: Software System
    - Description: Apple's mobile operating system, providing the runtime environment for iOS applications.
    - Responsibilities: Execute iOS applications, manage system resources, provide APIs for applications.
    - Security controls: iOS platform provides its own security controls, including sandboxing, permissions, and secure APIs, which applications built with Three20 benefit from.
  - - Name: App Store
    - Type: Software System
    - Description: Apple's official marketplace for distributing iOS applications to users.
    - Responsibilities: Host and distribute iOS applications, perform app review processes (including security checks).
    - Security controls: App Store review process includes basic security checks before applications are made available to users.
  - - Name: Apps using Three20
    - Type: Software System
    - Description: iOS applications developed using the Three20 library. These are the primary consumers of Three20's functionalities.
    - Responsibilities: Provide specific functionalities to users, utilize Three20 components for UI and utilities.
    - Security controls: Application developers are responsible for implementing security controls within their applications, including secure use of Three20 components and handling of user data.
  - - Name: Three20 Library
    - Type: Software System
    - Description: The Objective-C library itself, providing UI components and utilities for iOS development.
    - Responsibilities: Provide reusable UI elements and helper functions to simplify iOS development.
    - Security controls: Security controls within the Three20 library itself include secure coding practices, input validation within components (if applicable), and adherence to iOS security guidelines. (Historically, during active development).
  - - Name: iOS Developers
    - Type: Person
    - Description: Software developers who use the Three20 library to build iOS applications.
    - Responsibilities: Develop iOS applications, integrate and utilize the Three20 library, ensure secure and proper usage of the library.
    - Security controls: Developers are responsible for using Three20 securely and incorporating application-level security controls. Secure coding practices and awareness of potential vulnerabilities are key.
  - - Name: GitHub Repository
    - Type: Software System
    - Description: The online repository hosting the Three20 source code, issue tracking, and documentation.
    - Responsibilities: Version control, source code management, issue tracking, community collaboration (historically).
    - Security controls: GitHub provides security features like access control, vulnerability scanning (to some extent), and audit logs.
  - - Name: Xcode IDE
    - Type: Software System
    - Description: Apple's Integrated Development Environment used for iOS application development, including building and compiling Three20 and applications using it.
    - Responsibilities: Code editing, compilation, debugging, building iOS applications and libraries.
    - Security controls: Xcode provides tools for static analysis and code signing, contributing to the security of the build process.

## C4 CONTAINER

```mermaid
flowchart LR
    subgraph "Mobile User Device"
        subgraph "iOS Application"
            direction TB
            AppUI[Application UI Container]
            Three20Lib[Three20 Library Container]
            AppCode[Application Code Container]

            AppUI -- Uses --> Three20Lib
            AppUI -- Uses --> AppCode
            AppCode -- Uses --> Three20Lib
        end
        IOSPlatform[iOS Platform Container]
    end

    User[User] --> AppUI
    AppUI -- "iOS UI Framework" --> IOSPlatform
    AppCode -- "iOS SDK APIs" --> IOSPlatform
    Three20Lib -- "iOS SDK APIs" --> IOSPlatform


    linkStyle 0,1,2,3,4,5,6,7 stroke-width:2px,stroke:black;
```

- Container Diagram Elements:
  - - Name: iOS Application
    - Type: Software System
    - Description: The deployed iOS application on a user's device, incorporating the Three20 library.
    - Responsibilities: Provide application-specific functionality to the user, leveraging UI components and utilities from Three20.
    - Security controls: Application-level security controls, including input validation, secure data handling, secure communication, and adherence to iOS security best practices.
  - - Name: Application UI Container
    - Type: Container
    - Description: Represents the UI layer of the iOS application, built using both custom code and components from the Three20 library.
    - Responsibilities: Rendering the user interface, handling user interactions, displaying data.
    - Security controls: Input validation on user inputs received through the UI, secure rendering of content to prevent XSS (if applicable), and proper handling of sensitive data displayed in the UI.
  - - Name: Three20 Library Container
    - Type: Container
    - Description: The compiled Three20 library, integrated as a dependency within the iOS application.
    - Responsibilities: Provide reusable UI components, utility classes, and helper functions to the application.
    - Security controls: Historically, secure coding practices within the library, input validation within components, and adherence to iOS security guidelines. Now, security relies on the application developer to use the library securely and be aware of potential vulnerabilities.
  - - Name: Application Code Container
    - Type: Container
    - Description: The custom application-specific code developed by the iOS developer, which utilizes the Three20 library and iOS SDK APIs.
    - Responsibilities: Implement application logic, data processing, business rules, and integration with other systems or services.
    - Security controls: Application-level security controls, including authentication, authorization, secure data handling, secure communication, and proper integration with Three20 and iOS SDK APIs.
  - - Name: iOS Platform Container
    - Type: Container
    - Description: The iOS operating system environment on the user's device, providing system services and APIs.
    - Responsibilities: Manage application execution, provide access to device resources, enforce security policies.
    - Security controls: iOS platform security features, including sandboxing, permissions, memory protection, and secure APIs.

## DEPLOYMENT

```mermaid
flowchart LR
    subgraph "User Device (iOS)"
        subgraph "Deployment Environment"
            IOSDevice[iOS Device]
            subgraph "Operating System"
                IOS[iOS]
                subgraph "Application Sandbox"
                    iOSApp[iOS Application Instance]
                    Three20LibInstance[Three20 Library Instance]
                end
            end
        end
    end

    User[User] -- "Uses" --> iOSApp
    iOSApp -- "Runtime Dependency" --> Three20LibInstance
    iOSApp -- "Runs on" --> IOS
    IOS -- "Runs on" --> IOSDevice

    linkStyle 0,1,2,3,4,5 stroke-width:2px,stroke:black;
```

- Deployment Diagram Elements:
  - - Name: User Device (iOS)
    - Type: Infrastructure Node
    - Description: A physical iOS device (iPhone, iPad, iPod Touch) owned by the end-user.
    - Responsibilities: Run the iOS operating system and installed applications.
    - Security controls: Device-level security controls, such as device passcode/biometrics, device encryption, and remote management capabilities (MDM).
  - - Name: Deployment Environment
    - Type: Environment
    - Description: The iOS environment on the user's device where applications are deployed and executed.
    - Responsibilities: Provide the runtime environment for iOS applications.
    - Security controls: iOS operating system security features, application sandboxing, and resource management.
  - - Name: iOS
    - Type: Software
    - Description: The iOS operating system running on the user's device.
    - Responsibilities: Manage system resources, provide APIs for applications, enforce security policies, and run applications within sandboxes.
    - Security controls: iOS platform security features, including kernel-level security, sandboxing, code signing, and secure boot.
  - - Name: Application Sandbox
    - Type: Container
    - Description: The isolated environment in which each iOS application runs, providing security and resource isolation.
    - Responsibilities: Isolate application data and resources, restrict access to system resources based on permissions.
    - Security controls: iOS sandbox mechanism, which limits application access to the file system, network, and other system resources.
  - - Name: iOS Application Instance
    - Type: Software Instance
    - Description: A running instance of an iOS application that utilizes the Three20 library.
    - Responsibilities: Execute application code, provide user functionality, interact with the iOS platform and Three20 library.
    - Security controls: Application-level security controls implemented by the developer, running within the iOS sandbox.
  - - Name: Three20 Library Instance
    - Type: Software Instance
    - Description: The instance of the Three20 library loaded into the application's memory space at runtime.
    - Responsibilities: Provide UI components and utilities to the application instance.
    - Security controls: Security of the library instance depends on the security of the library code itself and how it is used by the application.

## BUILD

```mermaid
flowchart LR
    subgraph "Developer Workstation"
        Developer[Developer]
        XcodeIDE[Xcode IDE]
        SourceCode[Source Code (Three20 & App)]
    end
    subgraph "Build System (Historically Facebook's CI or Developer's Local)"
        BuildScripts[Build Scripts]
        Compiler[Objective-C Compiler]
        Linker[Linker]
        StaticAnalyzer[Static Analyzer (Optional)]
    end
    subgraph "Artifact Repository (Historically Facebook's or GitHub Releases)"
        BuildArtifacts[Build Artifacts (Three20 Library)]
    end

    Developer --> XcodeIDE
    XcodeIDE --> SourceCode
    SourceCode --> BuildScripts
    BuildScripts --> Compiler
    Compiler --> Linker
    Linker --> StaticAnalyzer
    StaticAnalyzer --> BuildArtifacts
    BuildScripts -- "Uses" --> XcodeIDE
    Compiler -- "Uses" --> XcodeIDE
    Linker -- "Uses" --> XcodeIDE
    StaticAnalyzer -- "Uses" --> XcodeIDE

    linkStyle 0,1,2,3,4,5,6,7,8,9,10,11 stroke-width:2px,stroke:black;
```

- Build Process Elements:
  - - Name: Developer
    - Type: Person
    - Description: A software developer working on the Three20 project or an application using Three20.
    - Responsibilities: Write code, commit changes, initiate builds.
    - Security controls: Secure coding practices, secure workstation, access control to source code repository.
  - - Name: Xcode IDE
    - Type: Software Application
    - Description: Apple's Integrated Development Environment used for developing and building iOS applications and libraries.
    - Responsibilities: Code editing, compilation, debugging, building, and packaging.
    - Security controls: Code signing, static analysis tools (integrated or plugins), secure build settings.
  - - Name: Source Code (Three20 & App)
    - Type: Data
    - Description: The Objective-C source code of the Three20 library and applications using it.
    - Responsibilities: Represent the codebase of the project.
    - Security controls: Version control system (Git), access control to the repository, code reviews.
  - - Name: Build Scripts
    - Type: Software
    - Description: Scripts (e.g., shell scripts, Xcode build scripts) that automate the build process.
    - Responsibilities: Define the build steps, compile code, link libraries, run tests, package artifacts.
    - Security controls: Secure scripting practices, access control to build scripts, integrity checks of scripts.
  - - Name: Compiler
    - Type: Software Application
    - Description: The Objective-C compiler (part of Xcode toolchain) that translates source code into machine code.
    - Responsibilities: Compile source code into object files.
    - Security controls: Compiler security features (e.g., stack protection, address space layout randomization - ASLR, enabled by Xcode build settings).
  - - Name: Linker
    - Type: Software Application
    - Description: The linker (part of Xcode toolchain) that combines object files and libraries into executable binaries or libraries.
    - Responsibilities: Link compiled object files and libraries to create the final build artifacts.
    - Security controls: Linker security features (e.g., ASLR, enabled by Xcode build settings).
  - - Name: Static Analyzer (Optional)
    - Type: Software Application
    - Description: Static analysis tools (e.g., Xcode's static analyzer, third-party SAST tools) that scan the source code for potential vulnerabilities and coding errors without executing the code.
    - Responsibilities: Identify potential security flaws and code quality issues in the source code.
    - Security controls: Configuration of static analysis rules, integration into the build process.
  - - Name: Build Artifacts (Three20 Library)
    - Type: Data
    - Description: The compiled Three20 library (e.g., static library or framework) and potentially application binaries.
    - Responsibilities: The output of the build process, ready for distribution or integration into applications.
    - Security controls: Code signing of build artifacts, secure storage of artifacts, access control to artifact repository.

# RISK ASSESSMENT

- Critical Business Processes:
  - Historically, the critical business process was the development and deployment of Facebook's iOS applications. Three20 aimed to streamline this process.
  - For other companies or developers using Three20, the critical business process was their own iOS application development lifecycle.
  - Now that the project is archived, there are no active critical business processes directly related to Three20 development. However, businesses still running applications built with Three20 are indirectly affected.

- Data Sensitivity:
  - Three20 itself, as a UI framework, does not directly handle sensitive data.
  - However, applications built using Three20 may handle various types of sensitive data, depending on their functionality (e.g., user credentials, personal information, financial data).
  - The sensitivity of data indirectly related to Three20 depends entirely on the applications that utilize it. If an application using Three20 has vulnerabilities, it could potentially expose sensitive data handled by that application.

# QUESTIONS & ASSUMPTIONS

- BUSINESS POSTURE:
  - Assumption: Three20 was primarily intended to benefit Facebook's iOS development efforts and was later open-sourced for broader community use.
  - Assumption: The primary business goal was to accelerate iOS development and improve code consistency.
  - Question: What was the specific business impact of using Three20 for Facebook in terms of development time and resource savings? (Historical context)

- SECURITY POSTURE:
  - Assumption: During active development, standard secure development practices were likely followed, but the level of rigor is unknown.
  - Assumption: As an open-source project, community contributions played a role in identifying and potentially fixing security issues (historically).
  - Question: Were there any known security vulnerabilities reported and fixed in Three20 during its active development? (Historical context)
  - Question: What security testing methodologies were employed for Three20 during its active development? (e.g., penetration testing, security audits) (Historical context)

- DESIGN:
  - Assumption: Three20 is designed as a static library or framework to be integrated into iOS applications.
  - Assumption: The architecture is primarily focused on providing UI components and utilities, with minimal backend dependencies or complex infrastructure.
  - Question: Are there any specific design decisions within Three20 that have significant security implications (e.g., handling of web content, data caching mechanisms)? (Technical deep dive question)
  - Question: What are the key dependencies of Three20 on external libraries or iOS SDK APIs, and what are the security considerations for these dependencies? (Dependency analysis question)