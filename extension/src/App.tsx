import { useState, useEffect } from "react";
import { Shield, Search, Globe, MonitorSmartphone, Activity, ArrowLeftRight, Wallet, History, CheckCircle } from "lucide-react";
import "./App.css";

function App() {
  const [activeTab, setActiveTab] = useState("settings"); // "settings", "transaction", "wallet", or "history"
  const [whoisEnabled, setWhoisEnabled] = useState(true);
  const [phishingEnabled, setPhishingEnabled] = useState(true);
  const [sandboxEnabled, setSandboxEnabled] = useState(false);
  const [searchEnabled, setSearchEnabled] = useState(false);
  const [transactionSimEnabled, setTransactionSimEnabled] = useState(true);
  
  // Transaction state
  const [currentTransaction, setCurrentTransaction] = useState<any>(null);
  const [simulationResult, setSimulationResult] = useState<any>(null);
  
  // Wallet state
  const [walletBalances, setWalletBalances] = useState<any>(null);
  const [transactionHistory, setTransactionHistory] = useState<any[]>([]);
  const [approvals, setApprovals] = useState<any[]>([]);
  const [threatsBlocked, setThreatsBlocked] = useState(0);

  // Load toggle states from storage on mount
  useEffect(() => {
    chrome.storage.local.get(
      ["whoisEnabled", "phishingEnabled", "sandboxEnabled", "searchEnabled", "transactionSimEnabled", "pendingTransaction"],
      (result) => {
        if (typeof result.whoisEnabled === "boolean")
          setWhoisEnabled(result.whoisEnabled);
        if (typeof result.phishingEnabled === "boolean")
          setPhishingEnabled(result.phishingEnabled);
        if (typeof result.sandboxEnabled === "boolean")
          setSandboxEnabled(result.sandboxEnabled);
        if (typeof result.searchEnabled === "boolean")
          setSearchEnabled(result.searchEnabled);
        if (typeof result.transactionSimEnabled === "boolean")
          setTransactionSimEnabled(result.transactionSimEnabled);
        if (result.pendingTransaction) {
          setCurrentTransaction(result.pendingTransaction);
          setActiveTab("transaction");
        }
      }
    );
  }, []);
  
  // Listen for transaction simulation results and wallet updates
  useEffect(() => {
    const listener = (message: any) => {
      if (message.type === "TRANSACTION_SIMULATION_RESULT") {
        setSimulationResult(message.result);
        setActiveTab("transaction");
        
        // Track threats blocked
        if (message.result.risk_level === "critical" || message.result.risk_level === "high") {
          setThreatsBlocked(prev => prev + 1);
        }
      } else if (message.type === "PENDING_TRANSACTION") {
        setCurrentTransaction(message.transaction);
        setActiveTab("transaction");
      } else if (message.type === "WALLET_UPDATE") {
        setWalletBalances(message.balances);
      } else if (message.type === "TRANSACTION_CONFIRMED") {
        setTransactionHistory(prev => [message.transaction, ...prev]);
        fetchWalletData();
      }
    };
    
    chrome.runtime.onMessage.addListener(listener);
    
    // Fetch wallet data on mount
    fetchWalletData();
    
    return () => {
      chrome.runtime.onMessage.removeListener(listener);
    };
  }, []);
  
  const fetchWalletData = async () => {
    try {
      const response = await fetch("http://localhost:5000/wallet");
      const data = await response.json();
      setWalletBalances(data.balances);
      setTransactionHistory(data.transactions || []);
      setApprovals(data.approvals || []);
    } catch (error) {
      console.error("Failed to fetch wallet data:", error);
    }
  };

  const handleToggle = (type: string, enabled: boolean) => {
    chrome.runtime.sendMessage({ type, enabled });
    // Persist to storage
    let key = "";
    if (type === "TOGGLE_WHOIS") key = "whoisEnabled";
    if (type === "TOGGLE_PHISHING") key = "phishingEnabled";
    if (type === "TOGGLE_SANDBOX") key = "sandboxEnabled";
    if (type === "TOGGLE_SEARCH") key = "searchEnabled";
    if (type === "TOGGLE_TRANSACTION_SIM") key = "transactionSimEnabled";
    if (key) chrome.storage.local.set({ [key]: enabled });
  };
  
  const getRiskColor = (risk: string) => {
    switch (risk?.toLowerCase()) {
      case "critical": return "#ef4444";
      case "high": return "#f97316";
      case "medium": return "#eab308";
      case "low": return "#22c55e";
      case "safe": return "#10b981";
      default: return "#6b7280";
    }
  };
  
  const getRiskLabel = (risk: string) => {
    if (!risk) return "Unknown";
    return risk.toUpperCase();
  };

  return (
    <div className="app-container vertical-rect">
      <div className="header">
        <h1>CryptoC</h1>
        <div className="tabs">
          <button 
            className={`tab-icon ${activeTab === "wallet" ? "active" : ""}`}
            onClick={() => setActiveTab("wallet")}
            title="Wallet"
          >
            <Wallet size={18} />
          </button>
          <button 
            className={`tab-icon ${activeTab === "transaction" ? "active" : ""}`}
            onClick={() => setActiveTab("transaction")}
            title="Transaction"
          >
            <Activity size={18} />
            {currentTransaction && <span className="notification-dot"></span>}
          </button>
          <button 
            className={`tab-icon ${activeTab === "history" ? "active" : ""}`}
            onClick={() => setActiveTab("history")}
            title="History"
          >
            <History size={18} />
          </button>
          <button 
            className={`tab-icon ${activeTab === "settings" ? "active" : ""}`}
            onClick={() => setActiveTab("settings")}
            title="Settings"
          >
            <Shield size={18} />
          </button>
        </div>
      </div>

      {activeTab === "settings" && (
        <div className="toggles">
        <div className="toggle-item">
          <div className="toggle-label">
            <Globe size={16} />
            <span>WHOIS Lookup</span>
          </div>
          <label className="switch">
            <input
              type="checkbox"
              checked={whoisEnabled}
              onChange={(e) => {
                setWhoisEnabled(e.target.checked);
                handleToggle("TOGGLE_WHOIS", e.target.checked);
              }}
            />
            <span className="slider"></span>
          </label>
        </div>

        <div className="toggle-item">
          <div className="toggle-label">
            <Shield size={18} />
            <span>Phishing Detection</span>
          </div>
          <label className="switch">
            <input
              type="checkbox"
              checked={phishingEnabled}
              onChange={(e) => {
                setPhishingEnabled(e.target.checked);
                handleToggle("TOGGLE_PHISHING", e.target.checked);
              }}
            />
            <span className="slider"></span>
          </label>
        </div>

        <div className="toggle-item">
          <div className="toggle-label">
            <MonitorSmartphone size={18} />
            <span>Sandbox Browser</span>
          </div>
          <label className="switch">
            <input
              type="checkbox"
              checked={sandboxEnabled}
              onChange={(e) => {
                setSandboxEnabled(e.target.checked);
                handleToggle("TOGGLE_SANDBOX", e.target.checked);
              }}
            />
            <span className="slider"></span>
          </label>
        </div>

        <div className="toggle-item">
          <div className="toggle-label">
            <Search size={18} />
            <span>Search with CryptoC</span>
          </div>
          <label className="switch">
            <input
              type="checkbox"
              checked={searchEnabled}
              onChange={(e) => {
                setSearchEnabled(e.target.checked);
                handleToggle("TOGGLE_SEARCH", e.target.checked);
              }}
            />
            <span className="slider"></span>
          </label>
        </div>
        
        <div className="toggle-item">
          <div className="toggle-label">
            <Activity size={18} />
            <span>Transaction Simulation</span>
          </div>
          <label className="switch">
            <input
              type="checkbox"
              checked={transactionSimEnabled}
              onChange={(e) => {
                setTransactionSimEnabled(e.target.checked);
                handleToggle("TOGGLE_TRANSACTION_SIM", e.target.checked);
              }}
            />
            <span className="slider"></span>
          </label>
        </div>
        </div>
      )}
      
      {activeTab === "transaction" && (
        <div className="transaction-view">
          {!currentTransaction && !simulationResult && (
            <div className="empty-state">
              <Activity size={48} color="#ccc" />
              <p>No pending transactions</p>
              <span className="hint">Transaction simulation will appear here when you interact with a dApp</span>
            </div>
          )}
          
          {currentTransaction && !simulationResult && (
            <div className="simulating">
              <div className="spinner"></div>
              <p>Simulating transaction...</p>
              <span className="hint">Analyzing blockchain effects</span>
            </div>
          )}
          
          {simulationResult && (
            <div className="simulation-result">
              <div 
                className="risk-banner"
                style={{ 
                  backgroundColor: getRiskColor(simulationResult.risk_level),
                  color: "white"
                }}
              >
                <Shield size={20} />
                <span>{getRiskLabel(simulationResult.risk_level)} RISK</span>
              </div>
              
              <div className="result-content">
                {simulationResult.risk_level === "critical" || simulationResult.risk_level === "high" ? (
                  <div className="warning-section">
                    <p className="warning-title">⚠️ Warning</p>
                    <p className="warning-message">{simulationResult.warning || "This transaction may be dangerous"}</p>
                    {simulationResult.effects && simulationResult.effects.length > 0 && (
                      <div className="effects-list">
                        <p className="effects-title">Transaction Effects:</p>
                        {simulationResult.effects.map((effect: any, idx: number) => (
                          <div key={idx} className="effect-item">
                            <ArrowLeftRight size={14} />
                            <span>{effect.description || JSON.stringify(effect)}</span>
                          </div>
                        ))}
                      </div>
                    )}
                  </div>
                ) : (
                  <div className="safe-section">
                    <p className="safe-title">✓ Transaction appears safe</p>
                    {simulationResult.effects && simulationResult.effects.length > 0 && (
                      <div className="effects-list">
                        <p className="effects-title">You will:</p>
                        {simulationResult.effects.map((effect: any, idx: number) => (
                          <div key={idx} className="effect-item safe">
                            <ArrowLeftRight size={14} />
                            <span>{effect.description || JSON.stringify(effect)}</span>
                          </div>
                        ))}
                      </div>
                    )}
                  </div>
                )}
                
                <button 
                  className="clear-button"
                  onClick={() => {
                    setCurrentTransaction(null);
                    setSimulationResult(null);
                    chrome.storage.local.remove("pendingTransaction");
                  }}
                >
                  Clear
                </button>
              </div>
            </div>
          )}
        </div>
      )}
      
      {activeTab === "wallet" && (
        <div className="wallet-view">
          <div className="stats-grid">
            <div className="stat-card">
              <div className="stat-label">Threats Blocked</div>
              <div className="stat-value">{threatsBlocked}</div>
            </div>
          </div>
          
          <div className="section-title">Balances</div>
          {!walletBalances ? (
            <div className="loading-state">
              <div className="spinner"></div>
              <p>Loading balances...</p>
            </div>
          ) : (
            <div className="balances-list">
              {Object.entries(walletBalances).map(([token, balance]: [string, any]) => (
                <div key={token} className="balance-item">
                  <div className="balance-token">
                    <span className="token-symbol">{token}</span>
                  </div>
                  <div className="balance-amount">
                    {typeof balance === 'number' ? balance.toLocaleString(undefined, {minimumFractionDigits: 2, maximumFractionDigits: 4}) : balance}
                  </div>
                </div>
              ))}
            </div>
          )}
          
          {approvals && approvals.length > 0 && (
            <>
              <div className="section-title">Active Approvals</div>
              <div className="approvals-list">
                {approvals.map((approval: any, idx: number) => (
                  <div key={idx} className="approval-item">
                    <div className="approval-info">
                      <div className="approval-token">{approval.token}</div>
                      <div className="approval-spender">{approval.spender?.slice(0, 10)}...</div>
                    </div>
                    <div className={`approval-amount ${approval.unlimited ? 'unlimited' : ''}`}>
                      {approval.unlimited ? 'UNLIMITED' : approval.amount}
                    </div>
                  </div>
                ))}
              </div>
            </>
          )}
        </div>
      )}
      
      {activeTab === "history" && (
        <div className="history-view">
          <div className="section-title">Transaction History</div>
          {transactionHistory.length === 0 ? (
            <div className="empty-state">
              <History size={48} color="#ccc" />
              <p>No transactions yet</p>
              <span className="hint">Your transaction history will appear here</span>
            </div>
          ) : (
            <div className="history-list">
              {transactionHistory.map((tx: any, idx: number) => (
                <div key={idx} className="history-item">
                  <div className="history-icon">
                    {tx.risk_level === "safe" || tx.risk_level === "low" ? (
                      <CheckCircle size={20} color="#22c55e" />
                    ) : (
                      <Shield size={20} style={{ color: getRiskColor(tx.risk_level) }} />
                    )}
                  </div>
                  <div className="history-info">
                    <div className="history-action">{tx.action || "Transaction"}</div>
                    <div className="history-time">{new Date(tx.timestamp).toLocaleString()}</div>
                  </div>
                  <div 
                    className="history-risk"
                    style={{ color: getRiskColor(tx.risk_level) }}
                  >
                    {getRiskLabel(tx.risk_level)}
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  );
}

export default App;
