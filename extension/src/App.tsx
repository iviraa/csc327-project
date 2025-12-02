import { useState, useEffect } from "react";
import { Shield, Search, Globe, MonitorSmartphone } from "lucide-react";
import "./App.css";

function App() {
  const [whoisEnabled, setWhoisEnabled] = useState(true);
  const [phishingEnabled, setPhishingEnabled] = useState(true);
  const [sandboxEnabled, setSandboxEnabled] = useState(false);
  const [searchEnabled, setSearchEnabled] = useState(false);

  // Load toggle states from storage on mount
  useEffect(() => {
    chrome.storage.local.get(
      ["whoisEnabled", "phishingEnabled", "sandboxEnabled", "searchEnabled"],
      (result) => {
        if (typeof result.whoisEnabled === "boolean")
          setWhoisEnabled(result.whoisEnabled);
        if (typeof result.phishingEnabled === "boolean")
          setPhishingEnabled(result.phishingEnabled);
        if (typeof result.sandboxEnabled === "boolean")
          setSandboxEnabled(result.sandboxEnabled);
        if (typeof result.searchEnabled === "boolean")
          setSearchEnabled(result.searchEnabled);
      }
    );
  }, []);

  const handleToggle = (type: string, enabled: boolean) => {
    chrome.runtime.sendMessage({ type, enabled });
    // Persist to storage
    let key = "";
    if (type === "TOGGLE_WHOIS") key = "whoisEnabled";
    if (type === "TOGGLE_PHISHING") key = "phishingEnabled";
    if (type === "TOGGLE_SANDBOX") key = "sandboxEnabled";
    if (type === "TOGGLE_SEARCH") key = "searchEnabled";
    if (key) chrome.storage.local.set({ [key]: enabled });
  };

  return (
    <div className="app-container vertical-rect">
      <div className="header">
        <h1>CryptoC</h1>
      </div>

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
      </div>
    </div>
  );
}

export default App;
