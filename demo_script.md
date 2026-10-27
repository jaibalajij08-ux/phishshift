# PhishShift — 3-to-5 Minute College Demonstration Script & Viva Defense

This guide provides an exact, word-for-word walkthrough and script for presenting **PhishShift** to your college professors, examiners, or project review panel.

---

## ⏱️ Minute-by-Minute Presentation Timeline

```
[0:00 - 1:00] Introduction & Problem Motivation (The Flaw of Black-Box Spam Filters)
[1:00 - 2:00] Architecture, Dataset Integrity & Safe Feature Engineering (NumPy)
[2:00 - 3:15] Live Interactive Demonstration (High Risk, Low Risk, and Abstention)
[3:15 - 4:15] Model Comparison, Boundary Cases & Robustness Perturbations
[4:15 - 5:00] Ethical Disclaimers, Conclusion & Q&A Readiness
```

---

## 🎙️ Step-by-Step Spoken Script

### 1. Opening & Problem Statement (0:00 - 1:00)
> *"Good morning/afternoon, professors. Today I am presenting **PhishShift — Message Risk Scanner**, an educational cybersecurity machine learning system that evaluates email and SMS messages for phishing risks.*
>
> *Most traditional email filters treat message safety as a binary black box: either 'Spam' or 'Not Spam'. But in real-world cybersecurity, social engineering attacks exploit human psychology—urgency, fear, and authority. Furthermore, binary classifiers often give users false confidence. PhishShift introduces a 3-way assessment: **Likely Phishing**, **Likely Legitimate**, or **Uncertain**—allowing the system to abstain and advise manual verification when messages are ambiguous.*
>
> *Most importantly, this is a defensive educational tool. It analyzes message tokens and defanged URLs entirely offline, without making live network requests or visiting dangerous links."*

---

### 2. Technologies & Data Engineering (1:00 - 2:00)
> *"For our technology stack, we used Python 3.12, Scikit-Learn, Pandas, Streamlit for the user interface, Matplotlib for metrics, and **NumPy** for numerical calculations, Shannon character entropy, and probability calibration.*
>
> *Our dataset contains 474 schema-validated messages across Email and SMS channels, balanced between legitimate and phishing examples. To avoid **data leakage**, we implemented campaign-aware splitting: all message variations belonging to a specific attack or operational template were isolated exclusively to either the training set or the held-out test set, ensuring our test metrics measure true generalization against unseen campaigns."*

---

### 3. Live Demonstration Walkthrough (2:00 - 3:15)
*(Action: Open the Streamlit web app in the browser)*

> *"Let me demonstrate the interactive application:*
>
> 1. ***Case 1: Phishing Bank Alert***  
>    *(Action: Select 'Phishing Email: Bank Credential Harvest' and click 'Analyze')*  
>    *'Here we see an urgent notice claiming unauthorized access. The system flags it as **Likely Phishing** with a high risk level. Notice the breakdown: it extracts observed indicators—such as urgent deadlines, credential harvesting terms, and an unauthorized IP address URL—and combines them with our primary Logistic Regression model score.'*
>
> 2. ***Case 2: Legitimate Operational Notice***  
>    *(Action: Select 'Legitimate Email: Scheduled IT Maintenance' and click 'Analyze')*  
>    *'Now let us test an operational notice. Even though words like 'maintenance' and 'intermittent' appear, the absence of credential-stealing links and the presence of operational context correctly yields **Likely Legitimate**.'*
>
> 3. ***Case 3: Borderline / Uncertain Message***  
>    *(Action: Select 'Ambiguous / Edge Case: Urgent Meeting Follow-up' and click 'Analyze')*  
>    *'Here is an edge case containing urgency ('URGENT', 'board call today') but no malicious payload. Rather than generating a false positive, the model probability falls into our abstention envelope [35%–65%], triggering an **Uncertain** warning and advising the user to verify the sender through a known channel.'*"

---

### 4. Model Benchmarking & Robustness (3:15 - 4:15)
*(Action: Open the Sidebar comparison table and Results charts)*

> *"We trained and compared three distinct detection paradigms:*
> 1. *A **Rule-Based Baseline** achieved 80% accuracy and 0 false positives, but missed 42.8% of paraphrased attacks.*
> 2. *Our **TF-IDF + Logistic Regression** pipeline was selected as the primary engine because its continuous, calibrated sigmoid probabilities enable reliable uncertainty estimation.*
> 3. *Our comparison **Multinomial Naive Bayes** pipeline achieved 84.4% accuracy.*
>
> *We also conducted an automated **Robustness Stress Test** across 8 safe perturbations—including casing changes, whitespace manipulation, and homoglyphs. When tested with character leetspeak ('p@ssw0rd'), the system safely shifted to **Uncertain**, preventing an adversarial false negative."*

---

### 5. Closing & Ethical Disclaimer (4:15 - 5:00)
> *"In summary, PhishShift demonstrates how combining interpretable indicators with machine learning and explicit uncertainty handling provides a far more resilient defensive training tool.*
>
> *All 26 automated unit tests pass in pytest, and full documentation, logs, charts, and an academic PDF report are included in the repository.*
>
> *Thank you, professors. I welcome any questions."*

---

## 💡 Top 5 Potential Professor Questions & Model Answers

**Q1: Why did you choose Logistic Regression as the primary model over Naive Bayes if Naive Bayes had a higher raw accuracy?**  
> **Answer**: *"While Naive Bayes scored higher raw accuracy on this split, its probability outputs are notoriously uncalibrated due to the naive feature independence assumption—often pushing scores unrealistically close to 0 or 1. Logistic Regression produces smooth, well-calibrated continuous probabilities, which are essential for our uncertainty thresholding and safe abstention logic."*

**Q2: How did you prevent data leakage during train/test split?**  
> **Answer**: *"Phishing attacks and corporate notifications often share template structures. If we used standard random splitting, near-duplicate variations of the same campaign would exist in both train and test partitions. We used `GroupShuffleSplit` on `campaign_id`, ensuring the test set consisted exclusively of completely unseen campaigns."*

**Q3: How was NumPy used in this project?**  
> **Answer**: *"NumPy was used extensively throughout the codebase: for calculating Shannon character entropy on URLs (`-np.sum(p * log2(p))`), computing array-based False Positive Rates (`FPR = FP / (FP + TN)`), vectorized class distribution statistics in the audit script, and numerical thresholding in the uncertainty calibration module."*

**Q4: How does PhishShift ensure user safety when analyzing messages with URLs?**  
> **Answer**: *"The scanner operates in a strictly passive, offline mode. It extracts lexical characteristics—such as raw IPv4 patterns, URL shortener domains, subdomain depth, and suspicious TLDs—using regular expressions and string parsing. It never makes HTTP requests, never queries DNS, and never renders HTML."*

**Q5: What are the main limitations of this system?**  
> **Answer**: *"First, statistical bag-of-words models can struggle with zero-day attacks crafted by modern generative AI using clean, polite vocabulary. Second, the system evaluates text content and URLs rather than raw email authentication headers (SPF, DKIM, DMARC). In a production environment, PhishShift would serve as a user-facing educational layer alongside email gateway protocol authentication."*
