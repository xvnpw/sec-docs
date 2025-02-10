# Mitigation Strategies Analysis for quantconnect/lean

## Mitigation Strategy: [Redundant Data Feeds (Lean-Integrated)](./mitigation_strategies/redundant_data_feeds__lean-integrated_.md)

**Mitigation Strategy:** Implement Multiple, Independent Data Feeds *within Lean*.

*   **Description:**
    1.  **Multiple `AddSecurity` Calls:** Within your Lean algorithm's `Initialize` method, use `AddSecurity` (or the appropriate method for your asset class) *multiple times*, once for each data provider you've selected.  Each call should specify the provider and any necessary connection parameters.  Example:
        ```csharp
        // Feed 1 (e.g., IEX)
        AddSecurity(SecurityType.Equity, "SPY", Resolution.Minute, Market.USA, true, 1, true, dataFeed: DataFeed.IEX);

        // Feed 2 (e.g., Polygon)
        AddSecurity(SecurityType.Equity, "SPY", Resolution.Minute, Market.USA, true, 1, true, dataFeed: DataFeed.Polygon);
        ```
    2.  **Custom Data Aggregator (Lean Class):** Create a custom class (inheriting from `PythonQuandl`, `TradeBar`, or a suitable base class) that acts as a data aggregator. This class will:
        *   Subscribe to data updates from *all* configured feeds (Lean handles the subscriptions based on the `AddSecurity` calls).
        *   Store the latest data point (price, volume, etc.) from each feed.
        *   Implement the comparison logic: Calculate the difference between data points from different feeds.
        *   Implement a threshold: If the difference exceeds the threshold, call a custom method (e.g., `OnError`).
    3.  **`OnError` Handling (Lean Method):** Override the `OnError` method in your algorithm.  This method will be called by your custom data aggregator when a discrepancy is detected.  Within `OnError`:
        *   Log the error details (which feeds are disagreeing, the magnitude of the difference).
        *   Potentially call `Liquidate()` to close all positions.
        *   Potentially call `SetStatus(AlgorithmStatus.Stopped)` to halt the algorithm.
    4.  **Fallback Logic (Within Aggregator or Algorithm):** Implement logic to handle feed failures.  If one feed consistently fails or provides anomalous data, the aggregator or algorithm should:
        *   Log the issue.
        *   Temporarily rely on the remaining feed(s).  This might involve using a weighted average or a designated "primary" and "secondary" feed.

*   **Threats Mitigated:**
    *   **Malicious Data Injection (High Severity):** Reduces reliance on a single, potentially compromised feed.
    *   **Erroneous Data Injection (High Severity):** Detects and mitigates the impact of errors from a single feed.
    *   **Data Feed Outages (Medium Severity):** Allows the algorithm to continue (potentially with reduced confidence) if one feed fails.

*   **Impact:**
    *   **Malicious/Erroneous Data Injection:** Significantly reduces risk by requiring multiple feeds to be compromised/erroneous simultaneously.
    *   **Data Feed Outages:** Reduces risk by providing redundancy.

*   **Currently Implemented:** (Example - Needs to be filled in based on the actual project)
    *   Basic `AddSecurity` calls for a single feed are present.  No redundant feeds or aggregator logic.

*   **Missing Implementation:** (Example - Needs to be filled in based on the actual project)
    *   Implementation of multiple `AddSecurity` calls for different providers.
    *   Creation of a custom data aggregator class.
    *   Integration of the aggregator with `OnError` and fallback logic.

## Mitigation Strategy: [Data Anomaly Detection (Lean Indicators)](./mitigation_strategies/data_anomaly_detection__lean_indicators_.md)

**Mitigation Strategy:** Implement Anomaly Detection Using Lean Indicators.

*   **Description:**
    1.  **Custom Indicator Creation:** Create custom indicators within Lean to calculate anomaly metrics.  Examples:
        *   **Z-Score Indicator:** Inherit from `IndicatorBase<IndicatorDataPoint>` and calculate the Z-score of the incoming price or volume data.
        *   **Moving Average Deviation Indicator:** Inherit from `IndicatorBase<IndicatorDataPoint>` and calculate the percentage difference between the current price and a moving average.
        *   **Percentile Indicator:**  Calculate historical percentiles and flag data outside predefined bounds.
    2.  **Indicator Registration:** In your algorithm's `Initialize` method, register your custom indicators using `RegisterIndicator`.  This ensures Lean updates the indicators with each new data point.
    3.  **Thresholding within `OnData`:** In your algorithm's `OnData` method (or the appropriate data handler):
        *   Access the current value of your custom indicators (e.g., `zscoreIndicator.Current.Value`).
        *   Compare the indicator value to a predefined threshold.
    4.  **Action on Anomaly:** If the threshold is exceeded:
        *   Log a detailed message using `Debug` or `Error`.
        *   Potentially adjust trading logic: reduce position size, widen stop-loss orders, or temporarily halt trading.  This logic should be carefully considered and backtested.
        *   Consider using `SetHoldings` to reduce exposure or `Liquidate` to close positions.
    5.  **Warm-up Period:** Ensure your indicators have a sufficient warm-up period (using `SetWarmUpPeriod`) before they are used for decision-making.

*   **Threats Mitigated:**
    *   **Malicious Data Injection (High Severity):** Detects unusual patterns that might indicate manipulation.
    *   **Erroneous Data Injection (High Severity):** Identifies data points outside the expected range.
    *   **Flash Crashes/Unusual Market Events (Medium Severity):** Provides early warning of extreme movements.

*   **Impact:**
    *   **Malicious/Erroneous Data Injection:** Reduces risk; effectiveness depends on the chosen indicators and thresholds.
    *   **Flash Crashes:** Provides early warning, allowing for risk mitigation.

*   **Currently Implemented:** (Example)
    *   A simple moving average indicator is used, but not for anomaly detection.

*   **Missing Implementation:** (Example)
    *   Creation of custom indicators specifically for anomaly detection (Z-score, percentile-based, etc.).
    *   Integration of these indicators with trading logic to trigger actions based on anomalies.

## Mitigation Strategy: [Strict Adherence to Lean's Data Handling (API Usage)](./mitigation_strategies/strict_adherence_to_lean's_data_handling__api_usage_.md)

**Mitigation Strategy:** Enforce Correct Usage of Lean's Data Access API.

*   **Description:**
    1.  **`History` Requests Only:**  *Exclusively* use Lean's `History` requests to obtain historical data.  Never attempt to access data outside the current time slice by manipulating timestamps or using other methods.
    2.  **Correct `History` Parameters:**  When using `History`:
        *   Specify the correct `Resolution`.
        *   Ensure the `endTime` parameter *never* includes future data relative to the current algorithm time.  Use `Time` property of algorithm.
        *   Use the appropriate overload of `History` for the data type you need (e.g., `History<TradeBar>`, `History<QuoteBar>`).
    3.  **Data Alignment Awareness:** Understand how Lean aligns data of different resolutions.  If you're using multiple resolutions, be aware of how data is consolidated and avoid making assumptions about the timing of data points.
    4.  **Avoid Direct Data Modification:** Do *not* directly modify the timestamps or values of data objects received from Lean.  If you need to transform data, create new data objects instead of modifying the originals.
    5. **Leverage Lean's Time Provider:** Use `this.Time` to get current algorithm time.

*   **Threats Mitigated:**
    *   **Data Snooping/Future Leakage (High Severity):** Prevents the algorithm from accessing future information, ensuring realistic backtesting and live trading.

*   **Impact:**
    *   **Data Snooping:** Eliminates the risk if implemented correctly.  This is a *critical* mitigation.

*   **Currently Implemented:** (Example)
    *   The algorithm mostly uses `History` correctly, but there are a few areas where the code could be made more explicit about time handling.

*   **Missing Implementation:** (Example)
    *   A thorough review of all data access code to ensure strict adherence to the guidelines above.
    *   Adding comments to clarify the time handling logic in complex sections of the code.

## Mitigation Strategy: [Brokerage API Rate Limiting (Lean-Aware Logic)](./mitigation_strategies/brokerage_api_rate_limiting__lean-aware_logic_.md)

**Mitigation Strategy:** Implement Rate Limit Handling within the Lean Algorithm.

*   **Description:**
    1.  **Brokerage Documentation:** Thoroughly review the brokerage's API documentation to understand their specific rate limits (requests per second, requests per minute, etc.).
    2.  **Lean's `BrokerageMessageHandler` (If Applicable):** Check if Lean provides a built-in `BrokerageMessageHandler` for your specific brokerage that handles rate limiting automatically. If so, ensure it's configured correctly.
    3.  **Custom Rate Limiting (If Necessary):** If Lean doesn't provide built-in handling, implement custom rate limiting logic *within your algorithm*:
        *   **Request Tracking:** Track the number of API requests made within specific time windows (e.g., using a queue or counter).
        *   **Delaying Requests:** If the rate limit is about to be exceeded, delay subsequent requests using `Task.Delay` or a similar mechanism.  Consider using an exponential backoff strategy.
        *   **Queueing Requests:** Implement a queue for outgoing API requests.  Process requests from the queue at a rate that respects the brokerage's limits.
        *   **Error Handling:** Handle rate limit errors (typically HTTP status code 429) gracefully.  Log the error, retry the request after a delay, and potentially reduce the overall request rate. Use `OnOrderEvent` to check order errors.
    4. **Use Lean constants:** Use `Globals.MaximumOrder`

