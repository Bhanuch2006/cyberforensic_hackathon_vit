# 🔍 ForensIQ - Cybersecurity Threat Detection API

Advanced threat detection and analysis pipeline with ML-based anomaly detection, attack chain correlation, MITRE ATT&CK mapping, and automated incident narratives.

## 🎯 Features

- **Module 1: Anomaly Detection** - Ensemble of 7 ML algorithms (Autoencoder, IsolationForest, HBOS, COPOD, ECOD, Statistical, N-gram)
- **Module 2: Correlation Engine** - Context-aware attack chain building with baseline analysis
- **Module 3: IP Enrichment** - Ground truth reputation scoring (70% dataset labels + 30% behavior)
- **Module 4: MITRE ATT&CK Mapping** - Automatic technique and tactic identification
- **Module 5: Story Generation** - Executive-ready incident narratives and recommendations

## 📦 Installation

### Prerequisites

- Python 3.8+
- Pre-trained models (from your notebooks)
- UNSW dataset

### Setup

```bash
# Clone repository
git clone https://github.com/yourusername/forensiq-api.git
cd forensiq-api

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Copy pre-trained models
cp path/to/autoencoder.pth output/models/
cp path/to/iforest.pkl output/models/
cp path/to/scaler.pkl output/models/

# Copy dataset
cp path/to/UNSW_prepared.csv data/

# Configure environment
cp .env.example .env
# Edit .env with your paths
