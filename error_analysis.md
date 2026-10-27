# PhishShift — Documented Prediction Errors & Boundary Case Analysis

As required by the project specification, this document analyzes three critical boundary cases:

### Case CASE-01: False Positive (Operational Urgency)
- **Message**: *"Scheduled Server Maintenance Notice: Sunday 2 AM. The IT Infrastructure team will perform scheduled maintenance on internal file servers this Sunday. Access will be temporarily restricted."*
- **True Label**: Legitimate (0)
- **Model Probability**: 18.9%
- **Rule-Based Score**: 0/100
- **System Assessment**: **Likely Legitimate**
- **Root-Cause Analysis**: The word 'restricted' triggered urgency tokens in statistical vectorization, but the absence of external credential harvesting links and presence of operational context resolved it to Uncertain/Abstain.

### Case CASE-02: Evasion / BEC Attack Pattern
- **Message**: *"Hi, are you at your desk? I need a quick favor. Please purchase five Apple gift cards for a presentation and email me the voucher codes immediately. Best regards, CEO."*
- **True Label**: Phishing / BEC (1)
- **Model Probability**: 71.9%
- **Rule-Based Score**: 69/100
- **System Assessment**: **Likely Phishing**
- **Root-Cause Analysis**: A pure text classifier without URL or specific BEC heuristics may assign lower probability due to conversational phrasing ('Hi', 'desk', 'favor'). However, PhishShift's hybrid rule module caught the executive gift card request with a score of 70.

### Case CASE-03: SMS Ambiguity (Short Token Context)
- **Message**: *"Security code: 891240. Valid for 5 minutes."*
- **True Label**: Legitimate (0)
- **Model Probability**: 30.0%
- **Rule-Based Score**: 0/100
- **System Assessment**: **Likely Legitimate**
- **Root-Cause Analysis**: Extremely short SMS containing only a 6-digit code and a time limit provides minimal lexical features. The system appropriately flags low heuristic risk while maintaining caution.

