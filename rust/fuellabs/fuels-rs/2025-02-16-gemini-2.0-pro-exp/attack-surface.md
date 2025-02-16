# Attack Surface Analysis for fuellabs/fuels-rs

## Attack Surface: [1. Malicious Fuel Node Interaction](./attack_surfaces/1__malicious_fuel_node_interaction.md)

*   *Description:* The application relies on a Fuel node for data and transaction submission. A compromised or malicious node can manipulate data, censor transactions, or attempt to exploit the SDK.
*   *How `fuels-rs` Contributes:* The SDK handles the communication protocol and data parsing with the Fuel node.  Vulnerabilities in this interaction are directly attributable to the SDK.
*   *Example:* A malicious node sends a fabricated block header claiming a transaction was included, when it was not.  The SDK, if not validating properly, might report this false confirmation to the application.
*   *Impact:* False transaction confirmations, incorrect balance reporting, denial-of-service, potential for triggering SDK vulnerabilities through malformed data.
*   *Risk Severity:* **High** (Potentially Critical if the application relies heavily on node responses without independent verification).
*   *Mitigation Strategies:*
    *   **(Developer):** Use the SDK's features for validating node responses (block headers, transaction proofs, receipts).  Implement robust error handling for unexpected node behavior.  Consider integrating with multiple Fuel nodes for redundancy and comparison.  Provide clear warnings to users if the connected node is not trusted.
    *   **(User):** Configure the application to connect to known, trusted Fuel nodes.  Be wary of default node configurations, especially in development environments.  If possible, run your own Fuel node.

## Attack Surface: [2. Transaction Replay/Front-running](./attack_surfaces/2__transaction_replayfront-running.md)

*   *Description:*  Improper nonce management or predictable transaction IDs could allow attackers to replay or front-run transactions.
    *   *How `fuels-rs` Contributes:* The SDK is responsible for constructing transactions, including setting nonces.  Its API and documentation guide developers on how to do this securely.
    *   *Example:* The SDK provides a function to fetch the next nonce, but the application developer doesn't use it correctly, leading to predictable nonces. An attacker replays a previously submitted transaction.
    *   *Impact:* Double-spending, unauthorized asset transfers, manipulation of contract state.
    *   *Risk Severity:* **High**
    *   *Mitigation Strategies:*
        *   **(Developer):**  Carefully follow the SDK's documentation and best practices for transaction construction.  Use the SDK's provided utilities for fetching and managing nonces.  Understand and implement appropriate gas price strategies to mitigate front-running.
        *   **(User):**  No direct mitigation, relies on the application developer using the SDK correctly.

