# Keycloak Admin MCP Guidelines

This document defines the engineering and documentation standards for `keycloak-admin-mcp`.
Our goal is **High-Trust, Zero-Ambiguity**. As a security-critical component
handling high-privilege administration, the code must explain *why* it is safe.

## 1. The "Lean" Documentation Standard

We adhere to the Guardian-Enhanced Docstring Standard. We avoid "reference bloat" by anchoring context at the module level, but we are **uncompromising** on security documentation.

### Module-Level Documentation (`//!`)
Every `lib.rs`, `main.rs`, and major `mod.rs` MUST start with a context block.
*   **Rationale**: Why does this module exist?
*   **Security Boundaries**: What data does it trust? What does it sanitize?
*   **References**: Links to `SECURITY.md`, RFCs, or Design Docs.

```rust
//! # Keycloak Admin Gateway
//!
//! Security enforcement point for the Admin MCP server.
//!
//! ## Rationale
//! Isolates high-privilege Keycloak credentials from the MCP server.
//! Performs token exchange (RFC 8693) to downscope permissions.
//!
//! ## Security Boundaries
//! * **Untrusted**: All incoming HTTP headers and bodies.
//! * **Trusted**: The internal OIDC discovery metadata.
//!
//! ## References
//! * **SPEC**: [OAuth 2.0 Token Exchange (RFC 8693)](https://tools.ietf.org/html/rfc8693)
//! * **SECURITY**: `SECURITY.md`
```

### Item-Level Documentation (`///`)
Public functions and structs focus on **usage**, **safety**, and **correctness**.

**Required Sections:**
1.  **Summary**: One active-verb sentence.
2.  **# Errors**: Explicitly state conditions for `Err` variants.
3.  **# Security**: **MANDATORY** for any function that:
    *   Handles tokens or credentials.
    *   Performs I/O (Network/Disk).
    *   Mutates state (POST/PUT/DELETE).
    *   Audit logs.
4.  **# Caveats**: Performance quirks or side effects (e.g., "Blocks thread for 200ms").

**Example:**

```rust
/// Executes a privileged administrative action.
///
/// Delegates the command to the Keycloak Admin REST API.
///
/// # Errors
/// * `AdminError::Forbidden` if the downscoped token lacks the role.
///
/// # Security
/// * **Audit**: Logs the action ID and Actor ID to the immutable ledger.
/// * **Redaction**: Secrets in the payload are masked before logging.
pub async fn execute_admin_command(...) -> Result<...> { ... }
```

## 2. The Principle of an Elegant Solution

An elegant solution is a simple, clever, and highly effective way to solve a problem, using the
minimum necessary resources (code, parts, or steps) to achieve a significant outcome. It often
solves related problems without brute force or unnecessary complexity, and it stays easy to
understand, maintain, and adapt. It prioritizes clarity, efficiency, and innovation over
brute-force methods, representing a high ratio of problem complexity to solution simplicity. A
truly elegant solution is more than just functional or safe; it is a system that is simple,
resilient, and self-sustaining. It does not merely solve a problem--it creates a framework that
prevents the problem from recurring. When approaching a task, especially a large-scale refactoring
or a new architectural design, strive for this level of elegance by considering the following:

1.  **From Static to Living:** Do not just build a static structure; cultivate a living system that
    can adapt and heal itself. The solution should not be a one-time event but a permanent,
    self-sustaining workflow.
2.  **Internalize Logic:** The system itself should be the primary agent of change and enforcement.
    Instead of relying on external scripts to police the structure, build tools that internalize
    the logic and guide contributors toward the correct path.
3.  **Incremental and Anti-Fragile:** Avoid "big bang" changes that concentrate risk or require
    brute-force effort. Design processes that are incremental, atomic, and reversible. The system
    should be anti-fragile, meaning it is resilient to failure and becomes stronger through small,
    contained corrections.
4.  **Clarity Through Tooling:** A well-designed tool is better than a page of instructions. An
    elegant solution provides tools that make the right way the easiest way, offering helpful
    guidance and automating complex tasks.
5.  **Aligns with Human Intuition:** An elegant solution ensures its physical reality matches its
    logical ideal. It should be as clear and intuitive to a human browsing the file system as it is
    to the automated tools that govern it. It reduces cognitive load and makes the correct path
    the most natural one.

By adhering to this principle, we create solutions that are not only robust and maintainable but also feel inevitable and simple to future contributors.

## 3. Engineering Standards
*   **Architecture**: `kc-admin-gateway` holds the keys. `kc-admin-mcp` is just a dumb client.
*   **Panic Free**: Library code must never panic.
*   **Dependencies**: Keep them shallow.
