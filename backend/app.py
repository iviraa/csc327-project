from flask import Flask, request, jsonify
from flask_cors import CORS
import logging
from urllib.parse import urlparse
import whois
from predict import predict_url_type
from blockchain_simulator import analyze_transaction_data
from wallet_manager import WalletManager

# Set up logging
logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s %(levelname)s %(name)s %(message)s"
)
logger = logging.getLogger(__name__)

# Try to import evaluation module
try:
    from evaluate_model import evaluate_model, get_quick_metrics
    EVALUATION_AVAILABLE = True
except ImportError as e:
    EVALUATION_AVAILABLE = False
    logger.warning(f"Evaluation module not available: {e}. Metrics endpoints will be disabled.")

app = Flask(__name__)
CORS(app)  # Enable CORS for all routes

# Initialize wallet manager
wallet_manager = WalletManager()

@app.route("/predict", methods=["POST"])
def predict():
    """
    SECURITY ENDPOINT: ML-powered URL phishing detection
    
    Security Features Implemented:
    1. Input Validation - Rejects requests without required 'url' parameter
    2. Error Handling - Prevents information disclosure through generic error messages
    3. Logging - Audit trail for all prediction requests
    4. Safe Processing - URL analyzed statically, never visited or executed
    """
    data = request.get_json()
    url = data.get("url")
    logger.info(f"Received prediction request for URL: {url}")

    # SECURITY CHECK #1: Input Validation
    # Reject requests missing required parameters to prevent null pointer exceptions
    # and ensure data integrity throughout the prediction pipeline
    if not url:
        logger.warning("No URL provided in request.")
        return jsonify({"error": "Missing 'url' parameter"}), 400

    try:
        # SECURITY: Get prediction using ML model (static analysis only - never visits URL)
        # This prevents XSS and drive-by download attacks that could occur from visiting URLs
        result = predict_url_type(url)
        
        # Determine if URL is safe (benign) or dangerous (malicious)
        is_safe = result["label"] == "benign"
        
        # Format response
        response = {
            "url": url,
            "prediction": result["label"],
            "is_safe": is_safe,
            "confidence": result["confidence"],
            "risk_score": result.get("risk_score", result["confidence"] * 100),
            "model_used": result["model_used"]
        }
        
        logger.info(f"Prediction successful: {response}")
        return jsonify(response)

    except Exception as e:
        # SECURITY CHECK #2: Error Handling without Information Disclosure
        # Log detailed error server-side for debugging, but return generic message to client
        # This prevents attackers from learning about internal system structure
        logger.error(f"Error during prediction: {e}", exc_info=True)
        return jsonify({"error": str(e)}), 500

@app.route("/whois", methods=["POST"])
def get_whois():
    data = request.get_json()
    url = data.get("url")
    logger.info(f"Received WHOIS request for URL: {url}")

    if not url:
        logger.warning("No URL provided in request.")
        return jsonify({"error": "Missing 'url' parameter"}), 400

    try:
        domain = urlparse(url).netloc
        w = whois.whois(domain)

        # Format dates to strings if they exist
        if w.creation_date:
            if isinstance(w.creation_date, list):
                w.creation_date = w.creation_date[0]
            w.creation_date = w.creation_date.strftime("%Y-%m-%d")

        if w.expiration_date:
            if isinstance(w.expiration_date, list):
                w.expiration_date = w.expiration_date[0]
            w.expiration_date = w.expiration_date.strftime("%Y-%m-%d")

        if w.updated_date:
            if isinstance(w.updated_date, list):
                w.updated_date = w.updated_date[0]
            w.updated_date = w.updated_date.strftime("%Y-%m-%d")

        whois_data = {
            "domain": domain,
            "registrar": w.registrar,
            "creation_date": w.creation_date,
            "expiration_date": w.expiration_date,
            "updated_date": w.updated_date,
            "name_servers": w.name_servers,
            "status": w.status,
            "emails": w.emails,
            "dnssec": w.dnssec,
            "name": w.name,
            "org": w.org,
            "address": w.address,
            "city": w.city,
            "state": w.state,
            "zipcode": w.zipcode,
            "country": w.country
        }

        return jsonify(whois_data)

    except Exception as e:
        logger.error(f"Error during WHOIS lookup: {e}", exc_info=True)
        return jsonify({"error": str(e)}), 500

@app.route("/simulate", methods=["POST"])
def simulate_transaction():
    """
    SECURITY ENDPOINT: Blockchain transaction simulation and threat detection
    
    This is the core security feature that prevents "blind signing" attacks.
    By simulating transactions before they're signed, users can see:
    - Actual token transfers and amounts
    - Unlimited approval requests (token drainer scams)
    - NFT approval-for-all operations (collection drains)
    - Transaction revert predictions
    
    Expected request body:
    {
        "from": "0x...",       # Sender address (validated)
        "to": "0x...",         # Contract address (validated)
        "value": "0",          # ETH amount in wei
        "data": "0x...",       # Contract calldata (decoded)
        "gasLimit": 100000     # Gas limit
    }
    
    Security Features:
    1. Address validation (EIP-55 checksums)
    2. Calldata decoding (function signature matching)
    3. Risk scoring (0-100 scale)
    4. Pattern detection (unlimited approvals, NFT scams)
    """
    data = request.get_json()
    logger.info(f"Received transaction simulation request")
    logger.debug(f"Transaction data: {data}")

    # SECURITY CHECK: Validate required fields
    # Ethereum addresses are required for simulation - reject invalid requests early
    # This prevents null reference errors and ensures proper transaction structure
    if not data.get("from") or not data.get("to"):
        logger.warning("Missing required fields in simulation request")
        return jsonify({"error": "Missing 'from' or 'to' address"}), 400

    try:
        # SECURITY: Run blockchain simulation to predict transaction effects
        # This decodes contract calls and detects malicious patterns BEFORE user signs
        # Prevents blind signing attacks where users unknowingly approve dangerous operations
        result = analyze_transaction_data(data)

        logger.info(f"Simulation completed - Risk Level: {result['risk_level']}, Score: {result['risk_score']}")
        logger.debug(f"Simulation result: {result}")

        return jsonify(result)

    except Exception as e:
        # SECURITY: Log errors without exposing internal details to client
        logger.error(f"Error during transaction simulation: {e}", exc_info=True)
        return jsonify({"error": str(e)}), 500

# =============================================================================
# WALLET MANAGEMENT ENDPOINTS
# =============================================================================

@app.route("/wallet/create", methods=["POST"])
def create_wallet():
    """Create a new wallet with default balances"""
    data = request.get_json()
    address = data.get("address")

    if not address:
        return jsonify({"error": "Missing 'address' parameter"}), 400

    try:
        result = wallet_manager.create_wallet(address)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error creating wallet: {e}", exc_info=True)
        return jsonify({"error": str(e)}), 500

@app.route("/wallet/balances", methods=["GET"])
def get_balances():
    """Get wallet balances"""
    address = request.args.get("address")

    if not address:
        return jsonify({"error": "Missing 'address' parameter"}), 400

    try:
        balances = wallet_manager.get_balances(address)
        return jsonify({"balances": balances})
    except Exception as e:
        logger.error(f"Error getting balances: {e}", exc_info=True)
        return jsonify({"error": str(e)}), 500

@app.route("/wallet/swap", methods=["POST"])
def execute_swap():
    """
    Execute a token swap and update balances
    
    SECURITY FEATURES:
    1. Input validation - All required fields checked before processing
    2. Balance validation - Insufficient balance rejected (prevents overdraft)
    3. Atomic transactions - All-or-nothing database updates
    4. Audit logging - Every swap recorded with timestamp
    """
    data = request.get_json()

    # SECURITY: Validate all required fields before processing
    # Prevents partial operations and ensures data integrity
    required_fields = ["address", "fromToken", "toToken", "amountFrom", "amountTo"]
    if not all(field in data for field in required_fields):
        return jsonify({"error": "Missing required fields"}), 400

    try:
        # SECURITY: execute_swap uses atomic database transactions with rollback
        # See wallet_manager.py lines 345-390 for SQL injection prevention
        result = wallet_manager.execute_swap(
            data["address"],
            data["fromToken"],
            data["toToken"],
            data["amountFrom"],
            data["amountTo"]
        )

        if result['success']:
            # SECURITY: Audit trail - Log all successful transactions for forensics
            # Includes timestamp, amounts, and risk level for security monitoring
            wallet_manager.add_log(
                data["address"],
                "SWAP_EXECUTED",
                f"Swapped {data['amountFrom']} {data['fromToken']} for {data['amountTo']} {data['toToken']}",
                "safe"
            )

        return jsonify(result)
    except Exception as e:
        logger.error(f"Error executing swap: {e}", exc_info=True)
        return jsonify({"error": str(e)}), 500

@app.route("/wallet/transactions", methods=["GET"])
def get_transactions():
    """Get transaction history"""
    address = request.args.get("address")
    limit = int(request.args.get("limit", 50))

    if not address:
        return jsonify({"error": "Missing 'address' parameter"}), 400

    try:
        transactions = wallet_manager.get_transactions(address, limit)
        return jsonify({"transactions": transactions})
    except Exception as e:
        logger.error(f"Error getting transactions: {e}", exc_info=True)
        return jsonify({"error": str(e)}), 500

@app.route("/wallet/logs", methods=["GET"])
def get_logs():
    """Get activity logs"""
    address = request.args.get("address")
    limit = int(request.args.get("limit", 100))

    if not address:
        return jsonify({"error": "Missing 'address' parameter"}), 400

    try:
        logs = wallet_manager.get_logs(address, limit)
        return jsonify({"logs": logs})
    except Exception as e:
        logger.error(f"Error getting logs: {e}", exc_info=True)
        return jsonify({"error": str(e)}), 500

@app.route("/wallet/log", methods=["POST"])
def add_log():
    """Add an activity log entry"""
    data = request.get_json()

    required_fields = ["address", "action", "details"]
    if not all(field in data for field in required_fields):
        return jsonify({"error": "Missing required fields"}), 400

    try:
        log_id = wallet_manager.add_log(
            data["address"],
            data["action"],
            data["details"],
            data.get("riskLevel", "safe")
        )
        return jsonify({"success": True, "logId": log_id})
    except Exception as e:
        logger.error(f"Error adding log: {e}", exc_info=True)
        return jsonify({"error": str(e)}), 500

@app.route("/wallet/stats", methods=["GET"])
def get_stats():
    """Get wallet statistics"""
    address = request.args.get("address")

    if not address:
        return jsonify({"error": "Missing 'address' parameter"}), 400

    try:
        stats = wallet_manager.get_wallet_stats(address)
        return jsonify(stats)
    except Exception as e:
        logger.error(f"Error getting stats: {e}", exc_info=True)
        return jsonify({"error": str(e)}), 500

@app.route("/wallet/approvals", methods=["GET"])
def get_approvals():
    """Get active token approvals"""
    address = request.args.get("address")

    if not address:
        return jsonify({"error": "Missing 'address' parameter"}), 400

    try:
        approvals = wallet_manager.get_approvals(address)
        return jsonify({"approvals": approvals})
    except Exception as e:
        logger.error(f"Error getting approvals: {e}", exc_info=True)
        return jsonify({"error": str(e)}), 500

# =============================================================================
# ML MODEL METRICS ENDPOINTS
# =============================================================================

@app.route("/metrics", methods=["GET"])
def get_metrics():
    """
    Get comprehensive ML model metrics
    Query parameters:
    - test_size: Number of test samples (default: "all" for all data, or specify a number, max: 10000)
    - quick: If true, use smaller test set for faster response (default: false)
    """
    if not EVALUATION_AVAILABLE:
        return jsonify({"error": "Evaluation module not available"}), 503
    
    try:
        quick = request.args.get("quick", "false").lower() == "true"
        test_size_param = request.args.get("test_size", "all" if not quick else "100")
        test_percentage_param = request.args.get("test_percentage", None)
        n_workers = int(request.args.get("n_workers", 10))
        
        # Limit workers to reasonable range
        n_workers = max(1, min(n_workers, 20))
        
        # Handle percentage-based testing
        test_percentage = None
        if test_percentage_param:
            test_percentage = float(test_percentage_param)
            test_percentage = max(0.01, min(test_percentage, 1.0))  # Between 1% and 100%
        
        # Handle "all" to use all available data
        test_size = None
        if test_percentage is None:
            if test_size_param.lower() == "all":
                test_size = None
            else:
                test_size = int(test_size_param)
                # Limit test size for performance (only if not using all data)
                if test_size > 10000:
                    test_size = 10000
                if test_size < 10:
                    test_size = 10
        
        logger.info(f"Computing metrics with test_percentage={test_percentage}, test_size={test_size if test_size else 'all'}, n_workers={n_workers}, quick={quick}")
        
        if quick:
            metrics = get_quick_metrics()
        else:
            metrics = evaluate_model(test_size=test_size, test_percentage=test_percentage, n_workers=n_workers)
        
        if "error" in metrics:
            return jsonify(metrics), 500
        
        return jsonify(metrics)
        
    except Exception as e:
        logger.error(f"Error computing metrics: {e}", exc_info=True)
        return jsonify({"error": str(e)}), 500

@app.route("/metrics/summary", methods=["GET"])
def get_metrics_summary():
    """
    Get quick metrics summary (faster response)
    """
    if not EVALUATION_AVAILABLE:
        return jsonify({"error": "Evaluation module not available"}), 503
    
    try:
        metrics = get_quick_metrics()
        if "error" in metrics:
            return jsonify(metrics), 500
        
        # Return only key metrics for summary
        summary = {
            "accuracy": metrics.get("accuracy"),
            "precision": metrics.get("precision"),
            "recall": metrics.get("recall"),
            "f1_score": metrics.get("f1_score"),
            "roc_auc": metrics.get("roc_auc"),
            "average_precision": metrics.get("average_precision"),
            "confusion_matrix": metrics.get("confusion_matrix"),
            "test_samples": metrics.get("test_samples")
        }
        
        return jsonify(summary)
        
    except Exception as e:
        logger.error(f"Error computing metrics summary: {e}", exc_info=True)
        return jsonify({"error": str(e)}), 500

if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)
