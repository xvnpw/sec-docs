# Threat Model Analysis for facebook/react

## Threat: [Cross-Site Scripting (XSS) via `dangerouslySetInnerHTML`](./threats/cross-site_scripting__xss__via__dangerouslysetinnerhtml_.md)

*   **Description:** An attacker injects malicious JavaScript code into a text input field (or other data source) that is later rendered using React's `dangerouslySetInnerHTML` prop *without* proper sanitization. The attacker crafts a payload that, when rendered in the context of another user's browser, executes the attacker's script. This is a direct misuse of a React-provided feature.
    *   **Impact:**
        *   Theft of user cookies and session tokens, leading to account takeover.
        *   Redirection of users to malicious websites.
        *   Modification of the page content (defacement).
        *   Keylogging and capturing of user input.
        *   Execution of arbitrary code within the user's browser, potentially leading to further exploitation.
    *   **Affected Component:** Any component that utilizes the `dangerouslySetInnerHTML` prop, specifically when handling user-supplied or untrusted data. This is a *function call* within a component, not the component itself.
    *   **Risk Severity:** Critical
    *   **Mitigation Strategies:**
        *   **Primary:** Avoid `dangerouslySetInnerHTML` whenever possible. Utilize React's standard JSX rendering, which provides automatic escaping of content.
        *   **If Unavoidable:** *Always* sanitize the HTML input using a robust and well-maintained sanitization library like DOMPurify *before* passing the content to `dangerouslySetInnerHTML`. Example: `<div dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(props.content) }} />`
        *   Ensure the sanitization library (e.g., DOMPurify) is kept up-to-date with the latest security patches.
        *   Implement a strong Content Security Policy (CSP) as a defense-in-depth measure to mitigate the impact of any successful XSS, even if sanitization fails.

## Threat: [State Exposure due to Improper Asynchronous Handling (Sensitive Data Leak)](./threats/state_exposure_due_to_improper_asynchronous_handling__sensitive_data_leak_.md)

*   **Description:** A React component makes an asynchronous request (e.g., fetching data or submitting a form).  Before the request completes, the component temporarily stores sensitive data (like a password or API key *incorrectly placed in state*) in its state. If the component unmounts or re-renders *before* the asynchronous operation completes and clears the state, that sensitive data might remain accessible in a previous state snapshot (observable via React DevTools or network traffic analysis). This is a direct consequence of how React handles state updates and component lifecycles.
    *   **Impact:**
        *   Exposure of sensitive user data (passwords, personal information, or improperly stored API keys).
        *   Potential for replay attacks if the exposed data includes authentication tokens.
    *   **Affected Component:** Any React component that manages state and performs asynchronous operations, particularly within lifecycle methods (e.g., `componentDidMount`, `componentDidUpdate`, or event handlers like `onClick` with promises). The issue lies within the component's *state management and asynchronous logic*.
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   Use `useEffect` (in functional components) with proper cleanup functions to cancel any pending asynchronous operations when the component unmounts. This prevents state updates after unmounting.
        *   Avoid storing sensitive data in component state for longer than absolutely necessary.  Ideally, sensitive data should *never* be stored in client-side state.
        *   Utilize a state management library (Redux, Zustand, etc.) that provides well-defined mechanisms for handling asynchronous operations and managing loading/error states, reducing the risk of race conditions.
        *   Consider using a "mounted" flag or a similar mechanism to prevent state updates after a component has unmounted, as an additional safety measure.

## Threat: [Server-Side XSS during Server-Side Rendering (SSR)](./threats/server-side_xss_during_server-side_rendering__ssr_.md)

*   **Description:** An attacker injects malicious JavaScript code into a text input field (or other data source). The application uses server-side rendering (SSR) with a framework like Next.js or Remix, which builds upon React. The *server* renders the React component, including the unsanitized user input, directly embedding the malicious script into the initial HTML sent to the client. This bypasses React's usual client-side escaping.
    *   **Impact:** Identical to traditional XSS: cookie theft, session hijacking, website defacement, keylogging, and potentially arbitrary code execution within the user's browser. The crucial difference is that the attack occurs *before* React hydration on the client-side.
    *   **Affected Component:** Any React component that is rendered on the server (using functions like `getServerSideProps` or `getStaticProps` in Next.js, or loaders in Remix) and includes user-supplied data *without* proper server-side sanitization. The vulnerability lies within the *server-side rendering logic* of the component.
    *   **Risk Severity:** Critical
    *   **Mitigation Strategies:**
        *   **Mandatory:** Sanitize *all* user input on the *server* before including it in the rendered HTML. Use a robust HTML sanitization library that is specifically designed and tested for server-side use (e.g., a server-compatible version of DOMPurify).
        *   Leverage the escaping mechanisms provided by the SSR framework itself (e.g., Next.js's built-in escaping functions).
        *   Implement a strong Content Security Policy (CSP) to limit the impact of any successful XSS, even if server-side sanitization fails. This is a crucial defense-in-depth measure.

## Threat: [Insecure Direct Object Reference (IDOR) Exploiting Component Prop Handling](./threats/insecure_direct_object_reference__idor__exploiting_component_prop_handling.md)

*   **Description:** A React component receives an ID (or other identifier) as a prop, and it uses this ID to fetch data from an API *without* performing adequate server-side authorization checks. An attacker modifies this prop (e.g., by manipulating the URL or using browser developer tools) to an ID they are *not* authorized to access.  The server, lacking proper checks, returns the sensitive data associated with the attacker-supplied ID. While IDOR is not *exclusive* to React, the common pattern of passing IDs as props makes it a relevant concern.
    *   **Impact:**
        *   Unauthorized access to sensitive data belonging to other users.
        *   Potential for data modification or deletion if the API allows write operations based on the manipulated ID.
    *   **Affected Component:** Any React component that receives an ID (or similar identifier) as a prop and uses that ID to fetch or manipulate data *without relying on robust server-side authorization*. The vulnerability is primarily on the *server-side*, but the component's prop handling is the *attack vector*.
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   **Crucial:** Implement robust server-side authorization checks. The server *must* verify that the currently authenticated user has the necessary permissions to access the resource identified by the ID, *regardless* of how that ID was provided to the client.
        *   Avoid using predictable or sequential IDs for sensitive resources.
        *   Use UUIDs or other cryptographically secure identifiers.
        *   Never rely solely on client-side validation or checks for authorization. Client-side logic can be bypassed.

