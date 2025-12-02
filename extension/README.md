# CryptoC Chrome Extension

Web3 Security Extension with ML-powered threat detection and transaction simulation.

## Features

- **ML-Powered URL Analysis** - Real-time phishing detection using machine learning
- **Transaction Simulation** - Analyze Web3 transactions before signing
- **WHOIS Lookup** - Domain information and registration details
- **Link Preview** - Hover over links to see security analysis
- **Sandbox Browser** - Safe browsing environment

## Development

### Prerequisites

- Node.js 18+
- npm or yarn
- Backend server running on `http://localhost:5000`

### Setup

1. **Install dependencies**
```bash
npm install
```

2. **Build the extension**
```bash
npm run build
```

3. **Load in Chrome**
   - Open Chrome and go to `chrome://extensions/`
   - Enable "Developer mode"
   - Click "Load unpacked"
   - Select the `dist` folder from the build output

### Development Mode

```bash
npm run dev
```

This will watch for changes and rebuild automatically.

## Backend Integration

The extension connects to the CryptoC backend API:

- `POST /predict` - ML URL safety analysis
- `POST /whois` - Domain WHOIS lookup
- `POST /simulate` - Transaction simulation
- `GET /wallet/balances` - Wallet balance queries
- `POST /wallet/swap` - Execute swaps

Make sure the backend is running on `http://localhost:5000` before using the extension.

## Usage

1. **URL Analysis**: Hover over any link to see security analysis
2. **Transaction Simulation**: Intercept Web3 transactions for analysis
3. **Settings**: Click the extension icon to configure features

## Project Structure

```
extension/
├── src/
│   ├── background/     # Service worker (background script)
│   ├── content/       # Content scripts (injected into pages)
│   ├── App.tsx        # Popup UI
│   └── assets/        # Icons and images
├── manifest.json      # Extension manifest
└── package.json       # Dependencies
```

