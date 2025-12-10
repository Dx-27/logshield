# LogShield — SOC-Grade Anomaly Detector 🛡️

LogShield is a lightweight, production-minded Streamlit app for log-based threat hunting. It ingests web access logs (Common/Combined Log Format), extracts vectorized features, runs an Isolation Forest to detect anomalous events, and produces a concise PDF incident report for SOC workflows.

---

## Key features
- Fast, vectorized log parsing using pandas (avoids Python loops)
- Feature extraction tuned for web attack patterns (entropy, URL shape, status codes)
- Isolation Forest-based unsupervised anomaly detection with adjustable sensitivity
- Interactive Streamlit dashboard with a Threat Feed, visual analytics, and PDF export
- SOC-friendly report generation with encoding-safe PDF export

---

## Quick start (local)

1. **Clone the repo**
```bash
git clone https://github.com/Dx-27/logshield.git
cd logshield
```

2. **Create & activate a virtual environment**
```bash
python -m venv venv
# macOS / Linux
source venv/bin/activate
# Windows (PowerShell)
venv\Scripts\Activate.ps1
```

3. **Install dependencies**
```bash
pip install -r requirements.txt
```

4. **Run the app**
```bash
streamlit run app.py
# or the script filename you use (e.g., logshield.py)
```

Open the URL Streamlit prints (usually `http://localhost:8501`). Upload an access log (CLF/Combined) and adjust Model Sensitivity to tune alerts.

---

## How it works (brief)
1. The app reads raw access logs and uses a single optimized regex to extract fields (ip, time, method, resource, status, size).
2. Vectorized feature engineering computes URL length, parameter counts, directory depth, entropy, request method scoring, status-based error flags, and IP frequency features.
3. Features are scaled and fed into an Isolation Forest. Predicted anomalies (model label -1) are surfaced in the UI and included in reports.
4. PDF export sanitizes text to avoid encoding errors and includes a top-N table of suspicious events.

---

## Tuning & Sensitivity
- Use the **Model Sensitivity** slider in the sidebar. It controls the `contamination` parameter passed to IsolationForest.
- Lower contamination → fewer alerts (less FP, risk of missing true positives). Default example: `0.02`.
- For thorough investigations, try multiple sensitivity values or ensemble different contamination settings and compare results.

---

## Limitations & caveats
- Parser expects Common/Combined Log Format. Non-standard logs may fail to parse — check raw file encoding and format.
- Isolation Forest is unsupervised: it detects statistical outliers, not specific CVEs. Investigate anomalies manually.
- Intended for local analysis and SOC workflows; not for automated blocking without human review.
- For high-volume logs, consider batching / streaming (Kafka, Spark).

---

## Extensibility ideas
- Add object-store connectors (S3, GCS) to ingest logs directly.
- Persist findings to ElasticSearch / SIEM for correlation and alerting.
- Combine anomaly detection with signature rules for better precision.
- Add authentication if exposing beyond localhost.
- Replace Isolation Forest with semi-supervised models when labeled data is available.

---

## Troubleshooting
- **Parsing fails / empty DataFrame**: ensure uploaded file follows CLF/Combined format and encoding (UTF-8 / Latin-1 fallback).
- **Slow on large files**: increase memory or preprocess logs; vectorized ops are faster but memory-bound for very large files.
- **PDF encoding issues**: the report generator sanitizes text; still pre-sanitize extremely large or binary payloads.

---

## License
MIT recommended. Add a `LICENSE` file if you publish the repo.
