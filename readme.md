# NetworkTrafficFiltering

AI-Powered Network Threat Detection with Real-Time Monitoring & LLM-Powered Explanations
FurrsahAI competition 2025
Team : 2nsi
---

## Overview

This project aims to build a scalable, real-time AI-powered threat detection system for network traffic, enhanced with Large Language Model (LLM) analysis for better interpretability.

We designed a system that:
- Detects and classifies malicious packets in real time.
- Leverages multiple ML models trained on diverse datasets.
- Analyzes logs in batch with an LLM to detect advanced threats (DoS/DDoS).
- Provides clear, human-readable justifications of detected anomalies.

---

## Architecture & Workflow

### Multi-Model ML Pipeline

We use three distinct machine learning models, each trained on a different dataset to ensure diversity and robustness across network domains:

| Detector       | Dataset                                | Kaggle Link                                                                                           |
|----------------|-----------------------------------------|--------------------------------------------------------------------------------------------------------|
| `detector3.py` | IoT Malicious Detection                 https://www.kaggle.com/datasets/agungpambudi/network-malware-detection-connection-analysis             |
| `detector2.py` | Network Intrusion Detection            | https://www.kaggle.com/code/istiakahammedeee/explainable-ai-techniques-for-intrusion-detection        |
| `detector1.py` | Network Traffic Malicious Activity     | https://www.kaggle.com/datasets/advaitnmenon/network-traffic-data-malicious-activity-detection        |

Each model is trained independently, but we apply a feature engineering and normalization process to unify input formats, enabling a combined prediction pipeline.

---

## LLM-Powered Threat Explanation

After real-time ML inference, all logs are batched and processed by an LLM (`LLM.py`) which:

- Analyzes collective patterns of packets.
- Detects complex attacks like DoS/DDoS missed by row-wise ML models.
- Provides natural language justifications for flagged threats.

The LLM runs using dependencies defined in `LLM requirements.txt`.

---

## Quick Start

### 1. Clone the repository
```bash
git clone https://github.com/ChadiDridi/NetworkTrafficFiltering.git
cd NetworkTrafficFiltering
```

### 2. Setup the Python virtual environment
```bash
python -m venv furrsah38
source furrsah38/bin/activate  
pip install -r requirements.txt
```

### 3. Run the detectors
Each detector can monitor different interfaces. Example:
```bash
python detector1.py eth0
```

### 4. Start the LLM analyzer 
```bash
pip install -r LLM\ requirements.txt
python LLM.py
```

---

## Datasets Used

| Dataset Name                              | Link                                                                                                   |
|-------------------------------------------|--------------------------------------------------------------------------------------------------------|
| IoT Malicious Detection                   | https://www.kaggle.com/datasets/agungpambudi/network-malware-detection-connection-analysis             |
| Network Malware Detection                 | https://www.kaggle.com/datasets/agungpambudi/network-malware-detection-connection-analysis             |
| Malicious Activity Detection              | https://www.kaggle.com/datasets/advaitnmenon/network-traffic-data-malicious-activity-detection         |

These datasets were chosen to train diverse models across different types of traffic, improving generalization.

---

## Live Demo

Fast-track demo (logs, Staging test on LAN attack via Kali linux, Dev Environment threats testing using attack.py):  
https://drive.google.com/drive/folders/1-rVJEEDVjGkgEXDbcasrKZ0K-uiZKJlg?usp=drive_link

---

## Built With

- Python
- XGBoost / Scikit-learn
- LLM (phi3/Transformers)
- Real-time packet tracking
- Unified ML + NLP log pipeline

---

## Inspirations and some cold starts

We didn't re invent the wheel but went through the datasets and code already deployed on kaggle notebooks as a start:
This helped us in choosing XGboost and check data's behavior from the existing code.
- https://www.kaggle.com/code/rem4000/xgboost-iot-malicious-detection-99-99-accuracy
- https://www.kaggle.com/code/istiakahammedeee/explainable-ai-techniques-for-intrusion-detection
Artifact : 
We adapted and extended the solution for real-time use, multi-dataset fusion, and LLM interpretability.

---

## License

This project is under the property of FurrsahAI competition. The solution belongs to the competition's holders.
