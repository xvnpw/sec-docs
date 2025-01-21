## Project Design Document: Lemmy

**Version:** 1.1
**Date:** October 26, 2023
**Author:** AI Software Architect

### 1. Introduction

This document provides an enhanced architectural design of the Lemmy project, an open-source link aggregator and forum software. This detailed design will serve as a robust foundation for subsequent threat modeling activities, enabling a comprehensive security analysis of the system. The design focuses on the key components, their interactions, and the data flows within the Lemmy application, providing more granular detail than the previous version.

### 2. Goals

*   Provide a more detailed definition of the major components of the Lemmy application, including their key responsibilities.
*   Elaborate on the interactions and data flow between these components, including specific data types and communication methods.
*   Offer more detailed visual representations of the system architecture and key processes.
*   Clearly identify the technologies and dependencies involved, with brief justifications where relevant.
*   Establish a stronger and more granular foundation for future threat modeling exercises.

### 3. High-Level Architecture

Lemmy employs a client-server architecture with a federated model. Individual Lemmy instances operate autonomously but can interact with each other to share content and user interactions via the ActivityPub protocol.

```mermaid
graph LR
    subgraph "User's Device"
        A("Web Browser")
        B("Mobile App")
    end
    C("Load Balancer")
    D("Lemmy Backend (Rust)")
    E("PostgreSQL Database")
    F("ActivityPub Implementation")
    G("Other Lemmy Instances")
    H("Email Server (SMTP)")
    I("Object Storage (Optional)")

    A --> C
    B --> C
    C --> D
    D --> E
    D --> F
    F --> G
    D --> H
    D --> I
```

### 4. Component Details

This section provides a more detailed breakdown of the key components within the Lemmy architecture, outlining their specific responsibilities and functionalities.

*   **User's Device:**
    *   Represents the client-side interface through which users interact with Lemmy.
        *   **Web Browser:** Utilizes standard web technologies (HTML, CSS, JavaScript) to render the user interface and communicate with the backend via HTTPS.
        *   **Mobile App:** Native or hybrid applications that interact with the Lemmy backend's API, typically using RESTful principles over HTTPS.

*   **Load Balancer:**
    *   Distributes incoming user traffic across multiple instances of the Lemmy backend to ensure high availability and scalability.
        *   May perform SSL/TLS termination, offloading encryption/decryption from the backend servers.
        *   Can implement health checks to ensure traffic is only routed to healthy backend instances.

*   **Lemmy Backend (Rust):**
    *   The core application logic, implemented in Rust for performance and safety.
        *   **API Gateway:** Handles incoming API requests from the frontend and other services.
        *   **Authentication and Authorization:** Manages user registration, login, session management (typically using JWTs or similar), and access control based on roles and permissions.
        *   **Content Management:**  Handles the creation, retrieval, updating, and deletion of posts, comments, communities, and user profiles. Includes input validation and sanitization.
        *   **Moderation Logic:** Implements rules and workflows for content moderation, including reporting, banning, and content removal.
        *   **Notification System:** Manages and delivers notifications to users (e.g., new replies, mentions).
        *   **Search Indexing:**  Integrates with a search engine (e.g., Elasticsearch) to provide search functionality for content and users.
        *   **Federation Handler:**  Manages the sending and receiving of ActivityPub activities.
        *   **Background Job Processing:** Handles asynchronous tasks like sending emails or processing federated updates.

*   **PostgreSQL Database:**
    *   The primary relational database used for persistent data storage.
        *   Stores user accounts (usernames, hashed passwords, email addresses, preferences).
        *   Stores content data (posts, comments, community details, timestamps, relationships).
        *   Stores voting information (upvotes, downvotes).
        *   Stores moderation logs and reports.
        *   Stores federation-related data (remote actors, inbox/outbox).

*   **ActivityPub Implementation:**
    *   Handles the federation aspects of Lemmy, enabling communication and data sharing with other compatible instances.
        *   **Outbox:**  Manages the creation and delivery of activities initiated by the local instance (e.g., new posts, follows).
        *   **Inbox:**  Receives and processes activities from remote instances.
        *   **Actor Management:**  Stores information about remote users and instances.
        *   **Signature Verification:** Verifies the authenticity of incoming ActivityPub requests using cryptographic signatures.

*   **Other Lemmy Instances:**
    *   Represents other independent Lemmy instances within the fediverse.
        *   Interacts with the local Lemmy instance by sending and receiving ActivityPub activities over HTTPS.

*   **Email Server (SMTP):**
    *   Used for sending transactional emails.
        *   Account verification emails during registration.
        *   Password reset emails.
        *   Notification emails (optional, depending on user preferences).

*   **Object Storage (Optional):**
    *   Provides scalable storage for media files.
        *   Stores images and videos uploaded by users.
        *   Can be a local file system or a cloud-based service like AWS S3, MinIO, or similar.

### 5. Data Flow Diagrams

This section provides more detailed illustrations of data flow for key user interactions, highlighting specific data elements and communication pathways.

#### 5.1. User Registration and Login (Detailed)

```mermaid
sequenceDiagram
    participant "Web Browser" as WB
    participant "Load Balancer" as LB
    participant "Lemmy Backend" as BE
    participant "PostgreSQL" as DB
    participant "Email Server" as ES

    WB->>LB: HTTPS POST /api/v1/register {username, email, password}
    LB->>BE: HTTPS POST /api/v1/register {username, email, password}
    BE->>BE: Validate input (format, length, uniqueness)
    BE->>DB: SELECT COUNT(*) FROM users WHERE username = ? OR email = ?
    DB-->>BE: Response (User/Email exists: true/false)
    alt User/Email does not exist
        BE->>BE: Hash password
        BE->>DB: INSERT INTO users (username, email, password_hash, ...) VALUES (?, ?, ?, ...)
        DB-->>BE: Response (Success, User ID)
        BE->>BE: Generate verification token
        BE->>DB: INSERT INTO user_tokens (user_id, token, type) VALUES (?, ?, 'verification')
        DB-->>BE: Response (Success)
        BE->>ES: Send verification email to user's email with token
        ES-->>BE: Response (Success/Failure)
        BE->>WB: HTTPS 201 Created {message: "Verification email sent"}
    else User/Email exists
        BE->>WB: HTTPS 409 Conflict {error: "Username or email already exists"}
    end

    WB->>LB: HTTPS POST /api/v1/login {username, password}
    LB->>BE: HTTPS POST /api/v1/login {username, password}
    BE->>DB: SELECT password_hash, salt FROM users WHERE username = ?
    DB-->>BE: Response (Hashed password, salt)
    BE->>BE: Verify password against hash
    alt Password valid
        BE->>BE: Generate session token (JWT)
        BE->>WB: HTTPS 200 OK {token: "...", expires_in: ...} with Set-Cookie
    else Password invalid
        BE->>WB: HTTPS 401 Unauthorized {error: "Invalid credentials"}
    end
```

#### 5.2. Posting Content (Detailed with Optional Media)

```mermaid
sequenceDiagram
    participant "Web Browser" as WB
    participant "Load Balancer" as LB
    participant "Lemmy Backend" as BE
    participant "PostgreSQL" as DB
    participant "ActivityPub" as AP
    participant "Object Storage" as OS

    WB->>LB: HTTPS POST /api/v1/post {community_id, title, url/body, ...} with Authorization
    LB->>BE: HTTPS POST /api/v1/post {community_id, title, url/body, ...} with Authorization
    BE->>BE: Authenticate user (verify JWT)
    BE->>BE: Validate input (length, format, community existence)
    opt Media Upload
        WB->>LB: HTTPS POST /api/v1/upload_media {file} with Authorization
        LB->>BE: HTTPS POST /api/v1/upload_media {file} with Authorization
        BE->>BE: Authenticate user
        BE->>OS: Store media file
        OS-->>BE: Response (Media URL)
        BE->>BE: Associate media URL with post data
    end
    BE->>DB: INSERT INTO posts (user_id, community_id, title, url, body, ...) VALUES (?, ?, ?, ?, ?, ...)
    DB-->>BE: Response (Success, Post ID)
    BE->>AP: Create ActivityPub "Create" activity (Announce to followers/community)
    AP->>Other: Deliver activity to federated instances
    BE->>WB: HTTPS 201 Created {post: {id: ..., ...}}
```

#### 5.3. Federated Interaction (Receiving and Processing a Post)

```mermaid
sequenceDiagram
    participant "Remote Instance" as Remote
    participant "Local Backend" as LocalBE
    participant "PostgreSQL" as DB

    Remote->>LocalBE: HTTPS POST /inbox (ActivityPub "Create" activity)
    LocalBE->>LocalBE: Verify signature of the activity
    LocalBE->>DB: SELECT actor_id FROM actors WHERE actor_url = ?
    DB-->>LocalBE: Response (Actor ID or null)
    alt Actor not found
        LocalBE->>LocalBE: Fetch actor details from remote instance
        LocalBE->>DB: INSERT INTO actors (...)
        DB-->>LocalBE: Response (New Actor ID)
    end
    LocalBE->>DB: SELECT post_id FROM posts WHERE ap_id = ?
    DB-->>LocalBE: Response (Post ID or null)
    alt Post does not exist
        LocalBE->>DB: INSERT INTO posts (ap_id, actor_id, content, ...) VALUES (?, ?, ?, ...)
        DB-->>LocalBE: Response (New Post ID)
    end
```

### 6. Security Considerations (Detailed)

This section expands on the security considerations, providing more specific examples and potential threats related to each component and data flow.

*   **User's Device:**
    *   **Threats:** Cross-Site Scripting (XSS), Man-in-the-Middle (MITM) attacks.
    *   **Mitigations:** Content Security Policy (CSP), HTTPS enforcement, secure cookie flags (HttpOnly, Secure).

*   **Load Balancer:**
    *   **Threats:** DDoS attacks, misconfiguration leading to information disclosure.
    *   **Mitigations:** Rate limiting, firewall rules, regular security audits.

*   **Lemmy Backend (Rust):**
    *   **Threats:** SQL Injection, Cross-Site Request Forgery (CSRF), authentication bypass, authorization flaws, insecure API endpoints.
    *   **Mitigations:** Input validation and sanitization, parameterized queries, CSRF tokens, robust authentication and authorization mechanisms (e.g., OAuth 2.0), API rate limiting, regular security audits and penetration testing.

*   **PostgreSQL Database:**
    *   **Threats:** Data breaches, unauthorized access, SQL injection (if not mitigated in the backend).
    *   **Mitigations:** Strong password policies, encryption at rest, network segmentation, least privilege access control, regular backups.

*   **ActivityPub Implementation:**
    *   **Threats:** Spoofed activities, denial-of-service through malicious federated traffic, information leakage through improperly handled federated data.
    *   **Mitigations:** Strict signature verification, rate limiting on incoming federated requests, careful handling and validation of data from remote instances.

*   **Email Server (SMTP):**
    *   **Threats:** Email spoofing, phishing attacks originating from the platform, insecure email transmission.
    *   **Mitigations:** SPF, DKIM, DMARC records, TLS encryption for email transmission.

*   **Object Storage (Optional):**
    *   **Threats:** Unauthorized access to stored media, data breaches.
    *   **Mitigations:** Access control policies, encryption at rest and in transit, secure generation of pre-signed URLs for access.

### 7. Technologies Used

*   **Backend:** Rust (chosen for performance, memory safety, and concurrency)
*   **Frontend:** TypeScript, React (common choice for building interactive web applications)
*   **Database:** PostgreSQL (robust, open-source relational database with good support for JSON and full-text search)
*   **Federation Protocol:** ActivityPub (the standard decentralized social networking protocol)
*   **Communication Protocol:** HTTPS (essential for secure communication)
*   **Load Balancer:** (e.g., Nginx, HAProxy - popular choices for their performance and features)
*   **Object Storage:** (e.g., AWS S3, MinIO - scalable and reliable storage solutions)
*   **Email Server:** SMTP (standard protocol for sending emails)

### 8. Future Considerations

*   Implementation details of specific API endpoints and their request/response structures.
*   Detailed deployment architecture, including containerization (Docker) and orchestration (Kubernetes).
*   Monitoring and logging infrastructure (e.g., Prometheus, Grafana, ELK stack).
*   Backup and recovery strategies and disaster recovery planning.
*   Specific security controls and policies to be implemented.

This improved design document provides a more granular and detailed understanding of the Lemmy project's architecture, offering a stronger foundation for comprehensive threat modeling and security analysis. The enhanced descriptions of components, data flows, and security considerations will be invaluable in identifying potential vulnerabilities and designing effective security mitigations.