# Architecture Documentation

## System Overview

The Cyber Risk Intelligence & Adaptive Defense Platform is a multi-module pipeline that processes raw security logs and produces prioritized, actionable threat intelligence.

---

## Module Descriptions

### 1. Ingestion Layer (`src/ingestion/`)

**Purpose:** Normalize diverse log formats into a unified event schema.

**Inputs:**
- Network flow logs (JSON, CSV)
- Authentication event logs
- Application access logs
- API gateway logs

**Outputs:** List of normalized event dictionaries

**Key class:** `LogParser`

---

### 2. Behavioural Anomaly Detection (`src/detection/`)

**Purpose:** Identify statistically abnormal behaviour patterns using ML.

**Techniques:**
- **Isolation Forest** — unsupervised anomaly scoring on tabular features
- **Statistical thresholds** — rule-based escalation for extreme signals

**Features used:**
- Failed login rate (1h window)
- Unique IPs accessed
- Data transferred (MB)
- Off-hours activity flag
- New device flag
- Privilege level
- API call rate
- Lateral movement hop count

**Output:** List of `AnomalyAlert` objects with type, severity, and score

---

### 3. Attack Chain Correlation (`src/correlation/`)

**Purpose:** Link isolated anomaly alerts from the same entity into temporal attack chains.

**Algorithm:**
1. Group alerts by entity
2. Sort by timestamp
3. Apply sliding time window (default: 1 hour)
4. Order events by attack stage taxonomy
5. Label chains using pattern matching

**Example chain:**
```
Network Scanning → Credential Misuse → Lateral Movement → Data Exfiltration
```

---

### 4. Dynamic Risk Scoring (`src/scoring/`)

**Purpose:** Produce a single 0–100 risk score per entity (user/device/service).

**Formula:**
```
Score = 0.35 × anomaly_severity
      + 0.20 × alert_frequency
      + 0.15 × privilege_level
      + 0.20 × data_sensitivity_accessed
      + 0.10 × historical_incident_rate
```

**Risk levels:**
| Score Range | Level    |
|-------------|----------|
| 80–100      | CRITICAL |
| 60–79       | HIGH     |
| 35–59       | MEDIUM   |
| 0–34        | LOW      |

---

### 5. Privacy Risk Monitoring (`src/privacy/`)

**Purpose:** Detect unauthorized or anomalous access to sensitive data.

**Rules:**
| Rule ID  | Signal                         | Severity |
|----------|--------------------------------|----------|
| PRIV-001 | Bulk download > 200MB          | HIGH     |
| PRIV-002 | Off-hours privileged access    | MEDIUM   |
| PRIV-003 | New device + sensitive data    | HIGH     |
| PRIV-004 | High API rate + bulk data      | CRITICAL |
| PRIV-005 | Lateral movement + data access | CRITICAL |

---

### 6. Adaptive Defense Advisor (`src/advisor/`)

**Purpose:** Translate risk context into ranked, actionable defense recommendations.

**Recommendation triggers:**

| Condition                        | Action                          |
|----------------------------------|---------------------------------|
| Score ≥ 80                       | Enforce MFA                     |
| Lateral movement in chain        | Isolate endpoint                |
| Score ≥ 60                       | Force password reset            |
| Data exfiltration in chain       | Block session                   |
| Score ≥ 50 + high privilege      | Revoke elevated privileges      |
| Score ≥ 35                       | Increase monitoring level       |
| Score ≥ 40                       | Prioritize patch deployment     |

---

### 7. Dashboard API (`src/dashboard/`)

**Purpose:** REST API layer for SOC dashboard integration.

**Endpoints:**

| Method | Path                    | Description                        |
|--------|-------------------------|------------------------------------|
| GET    | `/`                     | Health check                       |
| GET    | `/summary`              | Pipeline run summary               |
| GET    | `/risk-scores`          | All entity risk scores             |
| GET    | `/attack-chains`        | All correlated attack chains       |
| GET    | `/privacy-alerts`       | Privacy risk signals               |
| GET    | `/recommendations`      | Defense recommendations            |
| GET    | `/entity/{name}`        | Full entity threat profile         |

---

## Data Flow Diagram

```
┌─────────────────────────────────────────────────┐
│          DATA SOURCES                           │
│  Network Logs │ Auth Logs │ App Logs │ API Logs │
└──────────────────────┬──────────────────────────┘
                       │
                       ▼
            ┌──────────────────┐
            │  Log Parser      │  ← Normalize to unified schema
            └────────┬─────────┘
                     │
                     ▼
         ┌───────────────────────┐
         │  Anomaly Detector     │  ← Isolation Forest + Thresholds
         └───────────┬───────────┘
                     │
                     ▼
         ┌───────────────────────┐
         │  Attack Chain Builder │  ← Temporal correlation
         └───────────┬───────────┘
                     │
          ┌──────────┴──────────┐
          ▼                     ▼
  ┌───────────────┐    ┌─────────────────┐
  │  Risk Scorer  │    │ Privacy Monitor │
  └───────┬───────┘    └────────┬────────┘
          │                     │
          └──────────┬──────────┘
                     ▼
          ┌─────────────────────┐
          │   Defense Advisor   │  ← Context-aware mitigations
          └──────────┬──────────┘
                     │
                     ▼
          ┌─────────────────────┐
          │  Dashboard API      │  ← FastAPI REST layer
          └─────────────────────┘
```
