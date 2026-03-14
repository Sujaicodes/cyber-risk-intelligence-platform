# 🛡️ Cyber Risk Intelligence & Adaptive Defense Platform

> A unified intelligent cybersecurity system that monitors threats, correlates attack chains, scores risk dynamically, and recommends adaptive defenses — in real time.

![Python](https://img.shields.io/badge/Python-3.10+-blue?style=flat-square&logo=python)
![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)
![Status](https://img.shields.io/badge/Status-Hackathon%20Build-orange?style=flat-square)
![ML](https://img.shields.io/badge/ML-Scikit--learn%20%7C%20PyTorch-red?style=flat-square)

---

## 📌 Overview

With increasing complexity of cyber threats, organizations need intelligent systems capable of detecting attacks, prioritizing risks, and protecting sensitive data in real time.

This platform integrates **behavioural analytics**, **dynamic risk scoring**, and **incident correlation** into a single unified cybersecurity solution — going beyond traditional SIEM tools by reconstructing full attack chains and recommending adaptive defenses.

---

## ✨ Key Features

| Module | Description |
|--------|-------------|
| 🔎 **Multi-Layer Activity Monitor** | Ingests network, auth, and application logs |
| 🤖 **Behavioural Anomaly Detection** | ML-based detection of lateral movement, credential misuse, traffic anomalies |
| 🔗 **Attack Chain Correlation** | Links isolated events into full attack timelines |
| 📊 **Dynamic Risk Scoring** | Per-user, per-device, per-service risk scores |
| 🔐 **Privacy Risk Monitor** | Detects unauthorized data access and exfiltration signals |
| ⚠️ **Adaptive Defense Advisor** | Recommends context-aware mitigations (MFA, isolation, patching) |
| 📡 **Security Intelligence Dashboard** | Unified SOC-facing visualization layer |

---

## 🏗️ Architecture

```
Data Sources (Network / Identity / Application Logs)
                      ↓
           [ Preprocessing & Normalization Layer ]
                      ↓
       [ Behavioural ML Anomaly Detection Engine ]
          Isolation Forest | Autoencoder | LSTM
                      ↓
         [ Alert Correlation & Chain Builder ]
                      ↓
         [ Dynamic Cyber Risk Scoring Module ]
           User Score | Device Score | Service Score
                      ↓
    [ Privacy Monitor ]     [ Defense Advisor ]
                      ↓
         [ Security Intelligence Dashboard ]
```

---

## 📁 Project Structure

```
cyber-risk-platform/
├── src/
│   ├── ingestion/          # Log parsers and data collectors
│   ├── detection/          # Anomaly detection ML models
│   ├── correlation/        # Attack chain correlation engine
│   ├── scoring/            # Dynamic risk scoring logic
│   ├── privacy/            # Privacy risk monitoring module
│   ├── advisor/            # Adaptive defense recommendation engine
│   └── dashboard/          # API + dashboard backend
├── models/                 # Trained ML model artifacts
├── data/
│   └── sample_logs/        # Sample log datasets for testing
├── tests/                  # Unit and integration tests
├── scripts/                # Setup and utility scripts
├── docs/                   # Architecture diagrams and documentation
├── requirements.txt
├── docker-compose.yml
└── README.md
```

---

## 🚀 Quick Start

### 1. Clone the repository

```bash
git clone https://github.com/YOUR_USERNAME/cyber-risk-platform.git
cd cyber-risk-platform
```

### 2. Set up environment

```bash
python -m venv venv
source venv/bin/activate        # Linux/macOS
# or
venv\Scripts\activate           # Windows

pip install -r requirements.txt
```

### 3. Run with Docker (recommended)

```bash
docker-compose up --build
```

### 4. Run the detection pipeline manually

```bash
python scripts/run_pipeline.py --log-dir data/sample_logs/
```

---

## 🧠 ML Models Used

| Technique | Use Case |
|-----------|----------|
| **Isolation Forest** | General anomaly detection on tabular log data |
| **Autoencoder (PyTorch)** | Reconstruction error-based deep anomaly detection |
| **LSTM Time-Series Model** | Sequential behaviour deviation detection |
| **Rule-Based Correlation** | Attack chain linking from correlated alerts |

---

## 📊 Risk Scoring Formula

Each entity (user / device / service) is assigned a **dynamic risk score** from 0–100:

```
Risk Score = w1 × Anomaly_Severity
           + w2 × Alert_Frequency
           + w3 × Privilege_Level
           + w4 × Data_Sensitivity_Accessed
           + w5 × Historical_Incident_Rate
```

Weights are tunable per organization profile.

---

## 🔐 Privacy Risk Signals

The privacy module flags the following high-risk behaviors:

- Bulk sensitive data downloads (>X MB in Y minutes)
- Unauthorized database table queries
- After-hours access to PII-tagged resources
- Unusual cross-system data movement
- API calls with abnormal payload sizes

---

## ⚠️ Defense Recommendations

Based on risk score and attack chain context, the advisor suggests:

| Trigger Condition | Recommended Action |
|-------------------|--------------------|
| Score > 80 | Enforce MFA + alert SOC |
| Lateral movement detected | Isolate endpoint immediately |
| Credential anomaly | Force password reset |
| Unpatched CVE in active service | Prioritize patch deployment |
| Bulk data transfer | Block session + flag for review |

---

## 🧪 Testing

```bash
pytest tests/ -v
```

---

## 📄 Abstract

> With the increasing complexity of cyber threats, organizations require intelligent systems capable of detecting attacks, prioritizing risks, and protecting sensitive data in real time. This project proposes a **Cyber Risk Intelligence and Adaptive Defense Platform** that integrates behavioural analytics, risk scoring, and incident correlation into a unified cybersecurity solution.
>
> The platform continuously monitors multi-layer system activity including network traffic, authentication events, and application usage patterns. Machine learning based anomaly detection techniques are employed to identify suspicious behaviour such as abnormal login patterns, unusual data transfers, and network reconnaissance activities. Unlike traditional alerting systems, the proposed solution correlates multiple security events to reconstruct potential **attack chains**, enabling better situational awareness for security teams.
>
> A dynamic cyber risk scoring engine evaluates threat severity associated with users, devices, and services to support prioritized incident response. Additionally, a **privacy risk monitoring module** detects potential data exposure scenarios and unauthorized access to sensitive resources. Based on contextual threat intelligence, the platform provides adaptive defense recommendations such as enforcing MFA, isolating compromised endpoints, or prioritizing vulnerability patching.

---

## 🏆 Built For

This project was developed as a **hackathon submission** targeting real-world cybersecurity challenges in enterprise environments.

---

## 🤝 Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/new-module`)
3. Commit your changes (`git commit -m 'Add privacy detection module'`)
4. Push to the branch (`git push origin feature/new-module`)
5. Open a Pull Request

---

## 📜 License

This project is licensed under the MIT License — see [LICENSE](LICENSE) for details.
