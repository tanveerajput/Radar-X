# 🛡️ RADAR-X  
### Real-Time Ransomware Detection & Automated Mitigation System

Radar-X is a **real-time ransomware detection and response system** that identifies malicious behavior using **honeypots, behavioral indicators, and threat scoring**, and automatically initiates mitigation actions **before data encryption occurs**.

This project demonstrates **practical cybersecurity engineering**, combining detection logic, automated response, forensic reporting, and a live monitoring dashboard.

---

## 🎯 Why Radar-X?

Ransomware attacks typically:
- Encrypt files silently
- Spread rapidly across directories
- Cause irreversible data loss

Traditional antivirus solutions often react **after damage is done**.

**Radar-X focuses on early behavioral detection and rapid containment.**

---

## 🧠 Core Capabilities

- ✅ Honeypot-based ransomware detection  
- ✅ Threat scoring & incident classification  
- ✅ Automated mitigation workflow  
- ✅ Zero-encryption attack containment  
- ✅ Forensic & executive reporting  
- ✅ Live frontend dashboard  

---

## 🧩 How Radar-X Works (System Flow)

1. **Honeypots monitor file activity**
2. Suspicious modifications trigger **incident creation**
3. System calculates a **Threat Score (0–100)**
4. If threshold exceeded:
   - Attack is classified
   - Mitigation actions are executed
5. Incident reports are generated
6. Frontend dashboard updates in real time

---

## 🔍 Detection Mechanism

### Honeypot Strategy
- Multiple decoy files deployed (`decoy_0.txt` … `decoy_7.txt`)
- Any unauthorized modification is treated as malicious intent

### Indicators Used
- Honeypot file modification
- Number of decoys compromised
- Attack frequency
- Behavioral consistency

### Example Threat Scores (from real logs)
- 65 / 100 → Medium Risk  
- 70 / 100 → High Risk  
- 80 / 100 → Critical Risk  

---

## ⚙️ Automated Mitigation Actions

When ransomware behavior is detected, Radar-X can automatically:

- ✅ Kill malicious process  
- ✅ Lock sensitive user folders  
- ✅ Isolate system from network  
- ⚠️ Attempt backup recovery (if available)

These actions are logged with timestamps for audit and forensics.

---

## 📊 Proven Results (From Uploaded Incident Reports)

- 📁 **Files Encrypted:** 0  
- ⏱️ **Response Time:** 0.00 seconds (instant containment)  
- 🧨 **Threats Detected:** Multiple simulated ransomware incidents  
- 💾 **Data Loss:** NONE  

> All attacks were **contained before encryption**, validating the effectiveness of early-stage detection.

---

## 🧾 Incident & Forensic Reporting

Radar-X automatically generates:

### 1️⃣ Forensic Incident Reports
- Incident ID
- Detection time
- Threat score
- Compromised honeypots
- Indicators of attack

### 2️⃣ Executive Summary Reports
- Business impact
- Downtime estimation
- Data loss status
- Final containment result

These reports make Radar-X suitable for **SOC teams and enterprise environments**.

---

## 🖥️ Frontend Dashboard (Live Monitoring)

A lightweight frontend dashboard is included.

### Dashboard Features:
- System status view
- Recent alerts list
- Honeypot registry
- Auto-refresh (every 5 seconds)
- Federated learning rounds (if enabled)

### Frontend Stack:
- HTML (`index.html`)
- CSS (`style.css`)
- JavaScript (`app.js`)
- REST API integration (`/api/*`)

> Dashboard dynamically fetches and renders real incident data.

---

## 🛠️ Tech Stack

### Programming & Tools
- Python  
- JavaScript  
- HTML / CSS  
- VS Code  

### Libraries & Utilities
- psutil  
- watchdog  
- JSON-based logging  
- REST APIs  

### Architecture Style
- Event-driven detection
- Modular mitigation pipeline
- API-based frontend/backend separation

---

## 📁 Project Structure
Radar-X/
│
├── README.md                 # Project overview 
│
├── stage1_integrated.py      # ⭐ Main integrated ransomware detection system
│
├── file_monitor.py           # File system activity monitoring
├── process_monitor.py        # Suspicious process detection (CPU, IO, memory)
├── honeypot_manager.py       # Honeypot deployment & integrity checks
├── feature_extractor.py      # Feature extraction & normalization
├── ml_detector.py            # ML-assisted threat scoring logic
│
|___stage2_learn/
├── learn_from_incidents.py     # Main learning script
├── incident_dataset.csv        # Aggregated incident data
├── feature_history.csv         # Feature values over time
├── model_metrics.csv           # Accuracy, FP, FN, etc.
└── updated_thresholds.json     # Learned thresholds

├──stage3_mitigation              # Automated response scripts
│   ├── final_auto_fix.py
│   ├── fix_model.py
│   └── fix_threshold.py
│
├── incidents/                # Real ransomware incident logs
│   ├── incident_*.txt
│
├── alerts/                   # Generated alert JSON files
│   ├── alerts_*.json
│
├── frontend/                 # Monitoring dashboard
│   ├── index.html
│   ├── style.css
│   └── app.js
|
├── simulation/                     # ⭐ Controlled testing
│   ├── ransomware_simulator.exe
│   ├── README_simulation.md
│   └── test_files/
|
├── honeypots/                # Decoy files for detection
│   ├── decoy_0.txt
│   ├── decoy_1.txt
│   └── ...
│
├── data/                     # Runtime logs / supporting data
│   └── logs/reports/forensic reports
│
└── requirements.txt         


---

## 🚀 What This Project Demonstrates (For Recruiters)

- ✔️ Real ransomware detection logic (not just theory)
- ✔️ Automated security response design
- ✔️ Incident handling & forensics
- ✔️ Frontend + backend integration
- ✔️ Security mindset & system thinking
- ✔️ Industry-relevant cybersecurity skills

---

## 🔮 Future Enhancements

- Machine-learning-based threat scoring
- MITRE ATT&CK mapping
- SIEM integration (Azure Sentinel)
- Backup restoration engine
- Endpoint-scale deployment

---

## 👩‍💻 Author

**Tanvee Rajput**  
B.Tech | Cybersecurity Enthusiast  
Hackathon | Interested in **Cybersecurity

---

## 📜 Disclaimer

This project is developed for **academic, research, and learning purposes**.  
All attacks were simulated in a controlled environment.
