# Mitigation Strategies Analysis for grpc/grpc-go

## Mitigation Strategy: [Enforce Mutual TLS (mTLS)](./mitigation_strategies/enforce_mutual_tls__mtls_.md)

1.  **Server Configuration:** Use `grpc.Creds(credentials.NewTLS(&tls.Config{...}))` when creating the gRPC server.  Within the `tls.Config`, set `ClientAuth` to `tls.RequireAndVerifyClientCert`.  Provide a `CertPool` containing the CA certificate to `ClientCAs`.
2.  **Client Configuration:** Use `grpc.Creds(credentials.NewTLS(&tls.Config{...}))` when dialing from the client.  Load the client's certificate and private key, and provide them to the `tls.Config`.  Also, provide a `CertPool` containing the CA certificate to `RootCAs`.

*   **Threats Mitigated:**
    *   **Unauthorized Access (Severity: Critical):** Prevents clients without valid certificates from connecting.
    *   **Man-in-the-Middle (MITM) Attacks (Severity: Critical):**  Authenticates both client and server.
    *   **Eavesdropping (Severity: High):**  Provides encryption (inherent in TLS).

*   **Impact:**
    *   **Unauthorized Access:** Risk reduced to near zero.
    *   **MITM Attacks:** Risk significantly reduced.
    *   **Eavesdropping:** Risk significantly reduced.

*   **Currently Implemented:** Partially. Implemented between Service A and Service B (`serviceA/client.go`, `serviceB/server.go`).

*   **Missing Implementation:**
    *   Service C does not require client certificates (`serviceC/server.go`).

## Mitigation Strategy: [Use Per-RPC Credentials](./mitigation_strategies/use_per-rpc_credentials.md)

1.  **Client Implementation:**  Implement the `credentials.PerRPCCredentials` interface.  The `GetRequestMetadata` method adds the credentials (e.g., JWT) to the request metadata. Use `grpc.WithPerRPCCredentials(...)` when dialing.
2.  **Server Implementation:**  Use a unary or stream interceptor (`grpc.UnaryServerInterceptor` or `grpc.StreamServerInterceptor`) to extract the credentials from the request metadata (using `metadata.FromIncomingContext(ctx)`). Validate the credentials.

*   **Threats Mitigated:**
    *   **Unauthorized Access (Severity: Critical):**  Provides fine-grained access control.
    *   **Privilege Escalation (Severity: High):**  Enforces least privilege.

*   **Impact:**
    *   **Unauthorized Access:** Risk significantly reduced.
    *   **Privilege Escalation:** Risk significantly reduced.

*   **Currently Implemented:**  Not implemented.

*   **Missing Implementation:**  Not used in any service. Requires client and server-side changes, including interceptors.

## Mitigation Strategy: [Configure Keepalives](./mitigation_strategies/configure_keepalives.md)

1.  **Server-Side Configuration:**  Use `grpc.KeepaliveParams()` and `grpc.KeepaliveEnforcementPolicy()` when creating the gRPC server. Set appropriate values for `Time`, `Timeout`, `MinTime`, and `PermitWithoutStream`.
2.  **Client-Side Configuration (Optional):** Clients *can* use `grpc.WithKeepaliveParams()`, but the server's policy takes precedence.

*   **Threats Mitigated:**
    *   **Denial of Service (DoS) (Severity: Medium):**  Prevents holding open idle connections.
    *   **Resource Exhaustion (Severity: Medium):**  Frees up resources.

*   **Impact:**
    *   **DoS:** Risk reduced.
    *   **Resource Exhaustion:** Risk reduced.

*   **Currently Implemented:** Partially. Configured on Service B's server (`serviceB/server.go`), but with lenient settings.

*   **Missing Implementation:**
    *   Not configured on Service A or Service C servers.
    *   Service B settings need review.

## Mitigation Strategy: [Limit Concurrent Streams](./mitigation_strategies/limit_concurrent_streams.md)

1.  **Server-Side Configuration:**  Use `grpc.MaxConcurrentStreams()` when creating the gRPC server. Set a reasonable limit.

*   **Threats Mitigated:**
    *   **Denial of Service (DoS) (Severity: Medium):**  Limits streams per connection.
    *   **Resource Exhaustion (Severity: Medium):**  Controls resource use per client.

*   **Impact:**
    *   **DoS:** Risk reduced.
    *   **Resource Exhaustion:** Risk reduced.

*   **Currently Implemented:**  Not implemented.

*   **Missing Implementation:**  `grpc.MaxConcurrentStreams()` is not used in any server.

## Mitigation Strategy: [Set Connection and RPC Timeouts](./mitigation_strategies/set_connection_and_rpc_timeouts.md)

1.  **Client-Side Connection Timeout:**  Use `grpc.WithTimeout()` when dialing.
2.  **Client-Side RPC Timeout:**  Use `context.WithTimeout()` *before* each RPC call.
3.  **Server-Side Context Handling:** Server handlers should respect `ctx.Done()`.

*   **Threats Mitigated:**
    *   **Denial of Service (DoS) (Severity: Medium):**  Prevents long-lived connections/operations.
    *   **Resource Exhaustion (Severity: Medium):**  Enforces time limits.

*   **Impact:**
    *   **DoS:** Risk reduced.
    *   **Resource Exhaustion:** Risk reduced.

*   **Currently Implemented:** Partially. Service A's client uses RPC timeouts, but others don't. Server-side context handling is inconsistent.

*   **Missing Implementation:**
    *   Connection timeouts are inconsistent.
    *   RPC timeouts missing in Service B and C clients.
    *   Server-side context handling needs review.

## Mitigation Strategy: [Implement Rate Limiting (via Interceptor)](./mitigation_strategies/implement_rate_limiting__via_interceptor_.md)

1.  **Implement a Server-Side Interceptor:** Create a `grpc.UnaryServerInterceptor` or `grpc.StreamServerInterceptor`.
2.  **Track and Enforce:** Track request rates within the interceptor and return a `status.Error(codes.ResourceExhausted, "...")` if the limit is exceeded.

*   **Threats Mitigated:**
    *   **Denial of Service (DoS) (Severity: High):**  Prevents excessive requests.
    *   **Brute-Force Attacks (Severity: High):**  Limits authentication attempts.
    *   **Resource Exhaustion (Severity: Medium):**  Controls overall load.

*   **Impact:**
    *   **DoS:** Risk significantly reduced.
    *   **Brute-Force Attacks:** Risk significantly reduced.
    *   **Resource Exhaustion:** Risk reduced.

*   **Currently Implemented:**  Not implemented.

*   **Missing Implementation:**  Not implemented in any service. Requires a server-side interceptor.

## Mitigation Strategy: [Use `MaxHeaderListSize`](./mitigation_strategies/use__maxheaderlistsize_.md)

1. **Server-Side Configuration:** Use the `grpc.MaxHeaderListSize()` option when creating the gRPC server. Set a reasonable limit (in bytes).

*   **Threats Mitigated:**
    *   **Denial of Service (DoS) (Severity: Medium):** Prevents attacks with large headers.
    *   **Resource Exhaustion (Severity: Medium):** Limits memory consumption.

*   **Impact:**
    *   **DoS:** Risk reduced.
    *   **Resource Exhaustion:** Risk reduced.

    *   **Currently Implemented:** Not implemented.

    *   **Missing Implementation:** `grpc.MaxHeaderListSize()` is not used in any server configuration.

