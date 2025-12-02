// extension/src/content/Preview.tsx

import React from "react";
import "./Preview.css";
import {
  CheckIcon,
  AlertTriangleIcon,
  XIcon,
  ShieldIcon,
  LockIcon,
  ArrowRightIcon,
  DownloadIcon,
  InfoIcon,
  ClockIcon,
} from "lucide-react";

export interface SecurityInfo {
  isSafe: boolean | null;
  mlCategory?: string;
  confidence?: number;
}

export interface WhoisInfo {
  domain: string;
  registrar?: string;
  creation_date?: string;
  expiration_date?: string;
  updated_date?: string;
  name_servers?: string[];
  status?: string[];
  emails?: string[];
  dnssec?: boolean;
  name?: string;
  org?: string;
  address?: string;
  city?: string;
  state?: string;
  zipcode?: string;
  country?: string;
}

export interface LinkPreviewData {
  title: string;
  url: string;
  favicon?: string;
  isHttps?: boolean;
  redirectUrl?: string;
  isDownloadable?: boolean;
  fileType?: string;
  whois?: WhoisInfo;
}

interface PreviewProps {
  data: LinkPreviewData;
  position: { x: number; y: number };
  security: SecurityInfo | null;
  whoisEnabled: boolean;
  phishingEnabled: boolean;
}

type MLCategory = "benign" | "phishing" | "malware" | "defacement" | string;

interface TagAndMessage {
  tagClass: string;
  icon: React.ReactElement | null;
  label: string;
  sentence: string;
}

function getMLTagAndMessage(security: SecurityInfo): TagAndMessage {
  if (security.isSafe === null) {
    return {
      tagClass: "loading",
      icon: <ShieldIcon size={16} />,
      label: "Checking...",
      sentence: "Checking the website's safety...",
    };
  }

  // Always show confidence score after analysis
  const score = Math.round((security.confidence || 0.95) * 100);
  const tagClass = security.isSafe ? "safe" : "danger";

  return {
    tagClass,
    icon: null,
    label: `Score: ${score}%`,
    sentence: security.isSafe
      ? "This website is safe to visit."
      : "This website may be unsafe.",
  };
}

function getReputationTagAndMessage(
  whoisInfo: WhoisInfo | undefined
): TagAndMessage {
  if (!whoisInfo) {
    return {
      tagClass: "loading",
      icon: <ClockIcon size={16} />,
      label: "Checking...",
      sentence: "Checking domain reputation...",
    };
  }

  if (whoisInfo.creation_date) {
    const created = new Date(whoisInfo.creation_date);
    const now = new Date();
    const years = now.getFullYear() - created.getFullYear();

    if (years >= 5) {
      return {
        tagClass: "safe",
        icon: <CheckIcon size={16} />,
        label: "Established",
        sentence: "This domain has been registered for over 5 years.",
      };
    } else if (years < 1) {
      return {
        tagClass: "warning",
        icon: <AlertTriangleIcon size={16} />,
        label: "New Domain",
        sentence: "This domain was registered less than a year ago.",
      };
    } else {
      return {
        tagClass: "info",
        icon: <InfoIcon size={16} />,
        label: `${years} years`,
        sentence: `This domain has been registered for ${years} years.`,
      };
    }
  }

  return {
    tagClass: "warning",
    icon: <AlertTriangleIcon size={16} />,
    label: "Unknown",
    sentence: "Unable to determine domain age.",
  };
}

const getDomainReputation = (whoisInfo: WhoisInfo | undefined) => {
  if (!whoisInfo) return "Checking...";
  if (whoisInfo.creation_date) {
    const created = new Date(whoisInfo.creation_date);
    const now = new Date();
    const years = now.getFullYear() - created.getFullYear();
    if (years < 1) return "New Domain";
    if (years >= 5) return "5+ years";
    return `${years} years`;
  }
  return "Unknown";
};

const getStatusType = (
  security: SecurityInfo | null,
  domainReputation: string,
  isHttps: boolean | undefined
) => {
  // If isSafe is null or true AND domain age is 5+ years AND isHttps is true, status is safe
  if (
    (security?.isSafe === null || security?.isSafe === true) &&
    domainReputation === "5+ years" &&
    !isHttps
  ) {
    return "safe";
  }
  // If isSafe is false or any other case, status is danger
  if (security?.isSafe === false) return "danger";
  if (domainReputation === "New Domain") return "warning";
  if (security?.mlCategory === "phishing") return "danger";
  if (security?.mlCategory === "malware") return "danger";
  if (security?.mlCategory === "defacement") return "warning";
  if (security?.isSafe === null) return "warning";
  return "warning";
};

const Spinner: React.FC = () => <div className="peek-spinner" />;

const Preview: React.FC<PreviewProps> = ({
  data,
  position,
  security,
  whoisEnabled,
  phishingEnabled,
}) => {
  if (!phishingEnabled && !whoisEnabled) return null;

  // Add loading states
  const [httpsLoading, setHttpsLoading] = React.useState(true);
  const [redirectLoading, setRedirectLoading] = React.useState(true);
  const [downloadLoading, setDownloadLoading] = React.useState(true);

  // Simulate loading delays
  React.useEffect(() => {
    // HTTPS check delay
    setTimeout(() => {
      setHttpsLoading(false);
    }, 800);

    // Redirect check delay
    setTimeout(() => {
      setRedirectLoading(false);
    }, 1200);

    // Download check delay
    setTimeout(() => {
      setDownloadLoading(false);
    }, 1500);
  }, [data.url]); // Reset loading states when URL changes

  // Handle favicon error
  const handleFaviconError = (
    e: React.SyntheticEvent<HTMLImageElement, Event>
  ) => {
    const img = e.target as HTMLImageElement;
    img.style.display = "none"; // Hide broken favicon
  };

  // Helper functions for status
  const getStatusBadge = (
    text: string,
    type: string = "safe",
    isLoading: boolean = false
  ) => (
    <span
      className={`peek-status-badge peek-status-badge-${
        isLoading ? "loading" : type
      }`}
    >
      {isLoading ? <Spinner /> : text}
    </span>
  );

  const domainReputation = getDomainReputation(data.whois);
  const isLoading = !data.whois || security === null;
  const statusType = isLoading
    ? "loading"
    : getStatusType(security, domainReputation, data.isHttps);

  // Header icon and badge
  let headerIcon = (
    <CheckIcon
      size={15}
      style={{ color: "#22c55e", verticalAlign: "middle" }}
    />
  );
  let headerBadge = (
    <span
      className={`peek-header-safe peek-header-safe-xs ${
        isLoading ? "loading" : ""
      }`}
      style={{ display: "inline-flex", alignItems: "center" }}
    >
      {isLoading ? (
        <Spinner />
      ) : (
        `${Math.round((security?.confidence || 0.95) * 100)}%`
      )}
    </span>
  );
  if (statusType === "warning" || statusType === "danger") {
    headerBadge = (
      <span
        className={`peek-header-${statusType} peek-header-${statusType}-xs ${
          isLoading ? "loading" : ""
        }`}
        style={{ display: "inline-flex", alignItems: "center" }}
      >
        {isLoading ? (
          <Spinner />
        ) : (
          `${Math.round((security?.confidence || 0.95) * 100)}%`
        )}
      </span>
    );
  }

  // Threat detection label and status
  console.log("Security object:", security);
  console.log("Security isSafe:", security?.isSafe);
  console.log("Security mlCategory:", security?.mlCategory);

  let threatLabel = isLoading
    ? "Checking..."
    : security?.isSafe === null
    ? "Unknown"
    : security?.isSafe === false
    ? "Threats"
    : security?.mlCategory
    ? security.mlCategory.toLowerCase() === "phishing"
      ? "Phishing"
      : security.mlCategory.toLowerCase() === "malware"
      ? "Malware"
      : security.mlCategory.toLowerCase() === "defacement"
      ? "Defacement"
      : security.mlCategory.toLowerCase() === "benign"
      ? "Safe"
      : security.mlCategory.charAt(0).toUpperCase() +
        security.mlCategory.slice(1)
    : "Safe";

  let threatType = isLoading
    ? "loading"
    : security?.isSafe === null
    ? "warning"
    : security?.isSafe === false
    ? "danger"
    : security?.mlCategory
    ? ["phishing", "malware"].includes(security.mlCategory.toLowerCase())
      ? "danger"
      : ["defacement"].includes(security.mlCategory.toLowerCase())
      ? "warning"
      : security.mlCategory.toLowerCase() === "benign"
      ? "safe"
      : "warning"
    : "safe";

  console.log("Security:", security);

  // Let's also log the props being passed to getStatusBadge
  const threatBadge = getStatusBadge(threatLabel, threatType, isLoading);
  console.log("Status Badge Props:", {
    label: threatLabel,
    type: threatType,
    isLoading,
  });

  const mlTag = security ? getMLTagAndMessage(security) : null;

  return (
    <div
      className={`peek-preview-card peek-preview-xs ${position}`}
      style={{
        top: position.y,
        left: position.x,
        position: "fixed",
        minWidth: 286,
        maxWidth: 338,
        zIndex: 999999,
        padding: "16px 0 12px 0",
      }}
    >
      {/* Header */}
      <div
        className="peek-preview-header peek-header-xs"
        style={{
          display: "flex",
          justifyContent: "space-between",
          alignItems: "center",
          padding: "0 16px",
          marginBottom: 6,
        }}
      >
        {/* Favicon on left */}
        <div
          style={{
            display: "flex",
            alignItems: "center",
            minWidth: 24,
            minHeight: 24,
          }}
        >
          {data.favicon && (
            <img
              src={data.favicon}
              alt="favicon"
              className="peek-url-favicon"
              style={{ width: 24, height: 24, marginRight: 0 }}
              onError={handleFaviconError}
            />
          )}
        </div>
        {/* Status badge on right */}
        {headerBadge}
      </div>
      {/* URL directly below header */}
      <div
        className="peek-preview-url peek-url-xs"
        style={{
          padding: "8px 16px",
          textAlign: "center",
          marginBottom: 16,
          display: "flex",
          justifyContent: "center",
          margin: "0 16px 16px 16px",
        }}
      >
        <span
          className="peek-url-text peek-url-text-xs"
          style={{
            maxWidth: "100%",
            overflow: "hidden",
            textOverflow: "ellipsis",
            whiteSpace: "nowrap",
            display: "inline-block",
            verticalAlign: "middle",
            color: "#222",
            background: "#f3f4f6",
            borderRadius: "8px",
            padding: "4px 8px",
          }}
        >
          {data.url}
        </span>
      </div>
      {/* Security Checks */}
      <div
        className="peek-preview-list peek-list-xs"
        style={{ padding: "8px 16px 0" }}
      >
       
        <div className="peek-preview-row peek-row-xs">
          <ShieldIcon
            size={16}
            className="peek-row-icon"
            style={{ marginRight: 8 }}
          />
          <span className="peek-row-label peek-row-label-xs">
            Threat Detection
          </span>
          {threatBadge}
        </div>
        <div className="peek-preview-row peek-row-xs">
          <InfoIcon
            size={16}
            className="peek-row-icon"
            style={{ marginRight: 8 }}
          />
          <span className="peek-row-label peek-row-label-xs">
            Domain Reputation
          </span>
          {(() => {
            const reputation = getReputationTagAndMessage(data.whois);
            return getStatusBadge(
              reputation.label,
              reputation.tagClass,
              !data.whois
            );
          })()}
        </div>
        <div className="peek-preview-row peek-row-xs">
          <LockIcon
            size={16}
            className="peek-row-icon"
            style={{ marginRight: 8 }}
          />
          <span className="peek-row-label peek-row-label-xs">
            HTTPS Encryption
          </span>
          {getStatusBadge(
            data.isHttps ? "Not Secure" : "Secure",
            data.isHttps ? "danger" : "safe",
            httpsLoading
          )}
        </div>
        <div className="peek-preview-row peek-row-xs">
          <ArrowRightIcon
            size={16}
            className="peek-row-icon"
            style={{ marginRight: 8 }}
          />
          <span className="peek-row-label peek-row-label-xs">
            Redirect Analysis
          </span>
          {getStatusBadge(
            data.redirectUrl ? "Suspicious" : "Safe",
            data.redirectUrl ? "danger" : "safe",
            redirectLoading
          )}
        </div>
        <div className="peek-preview-row peek-row-xs">
          <DownloadIcon
            size={16}
            className="peek-row-icon"
            style={{ marginRight: 8 }}
          />
          <span className="peek-row-label peek-row-label-xs">
            Download Safety
          </span>
          {getStatusBadge(
            data.isDownloadable ? "Malicious" : "Clean",
            data.isDownloadable ? "danger" : "safe",
            downloadLoading
          )}
        </div>
        
      </div>
    </div>
  );
};

export default Preview;
