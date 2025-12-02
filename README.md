# CryptoC - Web3 Security Extension

A comprehensive Chrome extension that protects users from Web3 threats through machine learning-powered phishing detection and real-time transaction simulation. CryptoC intercepts data between websites and wallets to validate safety before any funds can move.

![Status](https://img.shields.io/badge/Status-Production%20Ready-green)
![License](https://img.shields.io/badge/License-MIT-blue)

## Overview

**CryptoC** is a Chrome extension that solves critical Web3 security problems:

1. **Phishing Protection** - ML-powered URL analysis (96.5% accuracy) detects zero-day phishing sites that static blacklists miss
2. **Blind Signing Prevention** - Real-time transaction simulation reveals the true financial outcome before users sign, preventing wallet drainers
3. **Approval Management** - Users can audit and revoke dangerous token approvals that leave wallets vulnerable

### Key Features

- **Real-time URL Analysis** - Automatic phishing detection using ML models
- **Transaction Simulation** - EVM-based transaction analysis before signing
- **Threat Detection** - Identifies unlimited approvals, NFT scams, and wallet drainers
- **Balance Tracking** - Real-time wallet balance updates
- **Portfolio Management** - Transaction history and approval management
- **Clean UI** - Modern, minimalist interface

## Architecture

```
web3-transaction-simulator/
├── backend/              # Python Flask API
│   ├── app.py           # Main Flask application
│   ├── blockchain_simulator.py  # Transaction simulation engine
│   ├── predict.py       # ML model integration
│   ├── wallet_manager.py # Wallet state management
│   ├── hf_model.py      # HuggingFace model wrapper
│   ├── data/            # ML training data
│   └── requirements.txt # Python dependencies
├── frontend/            # Demo Application (standalone HTML)
│   └── index.html      # Main demo application
├── extension/           # Chrome Extension
│   ├── src/            # Extension source code (TypeScript/React)
│   ├── manifest.json   # Extension manifest
│   └── package.json    # Extension dependencies
├── start-backend.sh     # Backend startup script
├── start-frontend.sh    # Frontend startup script
└── start-all.sh         # Start both servers
```

## Quick Start

### Prerequisites

- **Python 3.8+** (for backend)
- **Node.js 18+** (for frontend dev server, optional)
- **Modern web browser** (Chrome, Firefox, Edge)

### Installation

1. **Clone the repository**
```bash
git clone <repository-url>
cd web3-transaction-simulator
```

2. **Set up the backend**
```bash
cd backend
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install -r requirements.txt
```

3. **Start the servers**

**Option A: Start both servers (recommended)**
```bash
./start-all.sh
```

**Option B: Start separately**
```bash
# Terminal 1: Backend
./start-backend.sh

# Terminal 2: Frontend demo (optional - can also open index.html directly)
./start-frontend.sh
```

4. **Install the extension**
- **Extension**: See `extension/README.md` for Chrome extension setup and installation
- **Backend API**: `http://localhost:5000` (required for extension)
- **Demo Application** (optional): Open `frontend/index.html` in your browser, or visit `http://localhost:8000` if using dev server

## Usage Guide

### Chrome Extension

The extension automatically protects you as you browse:

- **Automatic URL Analysis**: Every page you visit is analyzed for phishing threats
- **Transaction Interception**: Web3 transactions are intercepted and simulated before signing
- **Risk Warnings**: Clear warnings show financial outcomes and detected threats
- **Approval Management**: Review and revoke dangerous token approvals

See `extension/README.md` for detailed extension setup and usage instructions.

### Demo Application (Optional)

The frontend is a **standalone demo application** that showcases CryptoC's security features. It includes:

- Interactive transaction simulation
- Real-time balance tracking
- Portfolio management
- Activity logging
- Four test scenarios (Safe Swap, Phishing, Token Drainer, NFT Scam)

### Testing Scenarios

The demo includes four test scenarios:

1. **Safe Swap** - Legitimate Uniswap transaction
2. **Phishing Site** - Typosquatting detection (op3nsea.io)
3. **Token Drainer** - Unlimited approval detection
4. **NFT Scam** - Collection approval detection

### How to Use the Demo

1. **Select a scenario** using the buttons at the top
2. **Check website safety** by clicking "Check if Safe" button
3. **Initiate a swap** by entering amounts and clicking "Swap"
4. **Review the analysis** in the popup panel
5. **Confirm or reject** the transaction based on risk assessment

### Features

- **Real-time Balance Updates** - Balances update automatically after transactions
- **Transaction History** - View all past transactions in Portfolio tab
- **Activity Logs** - Complete audit trail of all actions
- **Approval Management** - Review and revoke token approvals

## API Endpoints

### Backend API (Flask)

- `POST /predict` - ML-based URL safety analysis
  ```json
  {
    "url": "https://app.uniswap.org"
  }
  ```

- `POST /simulate` - Transaction simulation
  ```json
  {
    "from": "0x...",
    "to": "0x...",
    "value": "0",
    "data": "0x...",
    "gasLimit": 100000
  }
  ```

- `GET /wallet/balances` - Get wallet balances
- `POST /wallet/swap` - Execute swap transaction
- `GET /wallet/transactions` - Get transaction history
- `GET /wallet/logs` - Get activity logs

- `GET /metrics` - Comprehensive ML model metrics (F1, ROC-AUC, precision, recall, etc.)
  - Query parameters:
    - `test_size`: Number of test samples (default: 1000, max: 10000)
    - `quick`: Use smaller test set for faster response (default: false)
  ```bash
  # Full metrics with 1000 samples
  curl http://localhost:5000/metrics
  
  # Quick metrics with 100 samples
  curl http://localhost:5000/metrics?quick=true
  
  # Custom test size
  curl http://localhost:5000/metrics?test_size=500
  ```

- `GET /metrics/summary` - Quick metrics summary (key metrics only)
  ```bash
  curl http://localhost:5000/metrics/summary
  ```

### Metrics Response Format

The `/metrics` endpoint returns comprehensive evaluation metrics:

```json
{
  "accuracy": 0.9650,
  "precision": 0.9720,
  "recall": 0.9580,
  "f1_score": 0.9650,
  "roc_auc": 0.9920,
  "average_precision": 0.9850,
  "confusion_matrix": {
    "true_negative": 450,
    "false_positive": 20,
    "false_negative": 30,
    "true_positive": 500
  },
  "classification_report": {
    "Benign": {
      "precision": 0.9375,
      "recall": 0.9783,
      "f1-score": 0.9574
    },
    "Malicious": {
      "precision": 0.9615,
      "recall": 0.9434,
      "f1-score": 0.9524
    }
  },
  "roc_curve": {
    "fpr": [0.0, 0.01, ...],
    "tpr": [0.0, 0.95, ...],
    "thresholds": [1.0, 0.99, ...]
  },
  "precision_recall_curve": {
    "precision": [1.0, 0.99, ...],
    "recall": [0.0, 0.1, ...],
    "thresholds": [1.0, 0.99, ...]
  },
  "test_samples": 1000,
  "errors": 0,
  "model_info": {
    "test_size": 1000,
    "benign_samples": 470,
    "malicious_samples": 530
  }
}
```

## Testing

### Manual Testing

1. Test each scenario (Safe Swap, Phishing, Token Drainer, NFT Scam)
2. Verify balance updates after transactions
3. Check that warnings appear for dangerous transactions
4. Confirm transaction history is recorded

### Expected Behavior

- **Safe transactions**: Green "LOW RISK" banner, transaction proceeds normally
- **Dangerous transactions**: Red "CRITICAL RISK" banner, transaction blocked
- **Balance updates**: All balance displays update after successful transactions

## Project Structure

### Backend (`backend/`)

- `app.py` - Flask application with all API endpoints
- `blockchain_simulator.py` - Transaction simulation and signature decoding
- `predict.py` - ML model integration for URL analysis
- `evaluate_model.py` - ML model evaluation and metrics computation
- `wallet_manager.py` - Wallet state management with SQLite database
- `hf_model.py` - HuggingFace transformer model wrapper
- `data/` - ML training data (CSV files)

### Frontend (`frontend/`)

- `index.html` - Standalone demo application with embedded JavaScript
  - Uses Tailwind CSS via CDN
  - No build step required
  - All functionality in single file
  - Interactive demonstration of CryptoC security features

### Extension (`extension/`) - **Main Product**

- Chrome browser extension that provides real-time Web3 security protection
- Intercepts transactions and analyzes URLs automatically
- TypeScript/React codebase with Manifest V3
- See `extension/README.md` for setup instructions

## Security Features

### URL Analysis
- ML-based phishing detection (96.5% accuracy)
- Domain age analysis
- Typosquatting detection
- Certificate validation

### Transaction Analysis
- EVM transaction simulation
- Function signature decoding
- Approval pattern detection
- Risk scoring (0-100)

### Protection Mechanisms
- Unlimited approval detection
- NFT collection approval warnings
- Transaction effect prediction
- Real-time balance validation

## Development

### Backend Development

```bash
cd backend
source venv/bin/activate

# Optional: Train XGBoost model (for phishing detection)
./setup_xgboost.sh

# Optional: Set Alchemy API key (for real-time blockchain simulation)
export ALCHEMY_API_KEY="your-api-key-here"

# Start backend
python app.py
```

See `backend/XGBOOST_ALCHEMY_GUIDE.md` for detailed setup instructions.

### Frontend Development

The frontend demo is a standalone HTML file. For development:
- Edit `frontend/index.html` directly
- Use browser dev tools for debugging
- No build process required

### Adding New Scenarios

1. Add scenario to `scenarios` object in `index.html`
2. Add corresponding button in the UI
3. Update backend simulation logic if needed

## Performance

- **URL Analysis**: ~240ms average response time
- **Transaction Simulation**: ~150ms average response time
- **False Positive Rate**: <5%
- **Detection Accuracy**: 96.5%

### ML Model Metrics

The backend provides comprehensive ML model evaluation metrics:

- **Accuracy**: Overall classification accuracy
- **Precision**: True positives / (True positives + False positives)
- **Recall**: True positives / (True positives + False negatives)
- **F1 Score**: Harmonic mean of precision and recall
- **ROC-AUC**: Area under the ROC curve (0-1, higher is better)
- **Average Precision**: Area under the precision-recall curve
- **Confusion Matrix**: Detailed breakdown of predictions
- **ROC Curve**: Full ROC curve data for visualization
- **Precision-Recall Curve**: PR curve data for visualization

Access metrics via:
- `GET /metrics` - Full metrics with customizable test size
- `GET /metrics/summary` - Quick summary of key metrics

Example usage:
```bash
# Get full metrics (1000 test samples)
curl http://localhost:5000/metrics

# Get quick summary (100 test samples)
curl http://localhost:5000/metrics/summary

# Custom test size
curl http://localhost:5000/metrics?test_size=500
```

## Contributing

This is an academic project. For questions or contributions:
1. Review the codebase structure
2. Test your changes thoroughly
3. Ensure backward compatibility
4. Update documentation as needed

## License

MIT License - See LICENSE file for details

## Acknowledgments

- **Team CryptoC** - University of Southern Mississippi
- **CSC 327: Secure Software Development** - Course project
- **Web3 Security Community** - Research and insights

## Support

For issues or questions:
- Check the code comments for implementation details
- Review the API endpoints documentation
- Test with the provided scenarios

---

**Built for a safer Web3 ecosystem**
