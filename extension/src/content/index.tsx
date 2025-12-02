import Preview from "./Preview";
import ReactDOM from "react-dom/client";
import "./SandboxBrowser.css";

console.log("Preview root initialized, nothing should be rendered yet.");

// State management
let root: ReactDOM.Root | null = null;
let elem: HTMLElement | null = null;
let hoverTimeout: number | undefined;
let currentHoveredLink: HTMLAnchorElement | null = null;

// Store toggle states
let toggles = {
  whoisEnabled: true,
  phishingEnabled: true,
  sandboxEnabled: false,
  searchEnabled: false,
};

function ensurePreviewRoot(): void {
  if (!elem) {
    // Remove any existing preview containers
    document.querySelectorAll("#preview").forEach((el) => el.remove());

    elem = document.createElement("div");
    elem.id = "preview";
    elem.style.display = "none";
    document.body.appendChild(elem);
    root = ReactDOM.createRoot(elem);
  }
}

function removePreviewRoot(): void {
  if (elem) {
    root?.render(<></>);
    elem.style.display = "none";
  }
}

function showPreviewRoot(): void {
  if (elem) {
    elem.style.display = "block";
  }
}

interface WebsiteInfo {
  title: string;
  description: string;
  favicon: string;
}

function getWebsiteInfo(url: string): Promise<WebsiteInfo> {
  return new Promise((resolve) => {
    console.log("Sending FETCH_METADATA request for:", url);
    chrome.runtime.sendMessage({ type: "FETCH_METADATA", url }, (response) => {
      console.log("Received metadata response:", response);
      if (!response || !response.title) {
        console.warn("Empty or invalid metadata response for:", url);
      }
      resolve(response);
    });
  });
}

export interface SecurityInfo {
  isSafe: boolean | null;
  mlCategory?: string;
  confidence?: number;
}

function getWhoisInfo(url: string): Promise<any> {
  return new Promise((resolve) => {
    console.log("Sending WHOIS request for:", url);
    chrome.runtime.sendMessage({ type: "WHOIS_LOOKUP", url }, (response) => {
      console.log("Received WHOIS info:", response);
      if (!response) {
        console.warn("Empty WHOIS info response for:", url);
      }
      resolve(response);
    });
  });
}

function fetchToggles(): Promise<typeof toggles> {
  return new Promise((resolve) => {
    chrome.storage.local.get(
      ["whoisEnabled", "phishingEnabled", "sandboxEnabled", "searchEnabled"],
      (result) => {
        resolve({
          whoisEnabled: result.whoisEnabled !== false,
          phishingEnabled: result.phishingEnabled !== false,
          sandboxEnabled: result.sandboxEnabled === true,
          searchEnabled: result.searchEnabled === true,
        });
      }
    );
  });
}

// Update preview to respect toggles
async function showPreviewWithToggles(
  link: HTMLAnchorElement,
  position: PreviewPosition
) {
  toggles = await fetchToggles();

  // Get instant favicon from the domain
  const domain = new URL(link.href).origin;
  const instantFavicon = `${domain}/favicon.ico`;

  // Render immediately with loading state
  root?.render(
    <Preview
      data={{
        title: "",
        url: link.href,
        favicon: instantFavicon,
        whois: undefined,
      }}
      position={position}
      security={null}
      whoisEnabled={toggles.whoisEnabled}
      phishingEnabled={toggles.phishingEnabled}
    />
  );

  try {
    // Fetch data in parallel
    const [metadata, security, whois] = await Promise.all([
      getWebsiteInfo(link.href),
      toggles.phishingEnabled
        ? fetchMLResult(link.href)
        : Promise.resolve(null),
      toggles.whoisEnabled ? getWhoisInfo(link.href) : Promise.resolve(null),
    ]);

    // Update preview with fetched data, keeping the instant favicon if no metadata favicon
    root?.render(
      <Preview
        data={{
          title: metadata?.title || "",
          url: link.href,
          favicon: metadata?.favicon || instantFavicon,
          whois: toggles.whoisEnabled ? whois : undefined,
        }}
        position={position}
        security={toggles.phishingEnabled ? security : null}
        whoisEnabled={toggles.whoisEnabled}
        phishingEnabled={toggles.phishingEnabled}
      />
    );
  } catch (error) {
    console.error("Error fetching preview data:", error);
    // Keep the loading state visible on error
  }
}

// Update onLinkEnter to use showPreviewWithToggles
function onLinkEnter(e: Event): void {
  const link = e.currentTarget as HTMLAnchorElement;
  currentHoveredLink = link;
  hoverTimeout = window.setTimeout(async () => {
    if (currentHoveredLink !== link) return;
    ensurePreviewRoot();
    showPreviewRoot();
    root?.render(<></>); // Clear previous
    await showPreviewWithToggles(
      link,
      getPreviewPosition(link.getBoundingClientRect())
    );
  }, 200);
}

function onLinkLeave(e: Event): void {
  const link = e.currentTarget as HTMLAnchorElement;
  if (hoverTimeout) {
    clearTimeout(hoverTimeout);
  }
  if (currentHoveredLink === link) {
    currentHoveredLink = null;
    removePreviewRoot();
  }
}

// Attach listeners to all links to open in sandbox
function attachListeners(): void {
  document.querySelectorAll("a[href]").forEach((link) => {
    link.removeEventListener("mouseenter", onLinkEnter);
    link.removeEventListener("mouseleave", onLinkLeave);
    link.addEventListener("mouseenter", onLinkEnter);
    link.addEventListener("mouseleave", onLinkLeave);
    // Removed sandboxClickHandler for normal clicks
  });
}

// For dynamic content, re-attach listeners as needed
const observer = new MutationObserver(attachListeners);
observer.observe(document.body, { childList: true, subtree: true });
attachListeners();

// Cleanup on page unload
window.addEventListener("unload", () => {
  observer.disconnect();
  if (hoverTimeout) {
    clearTimeout(hoverTimeout);
  }
  removePreviewRoot();
});

document.addEventListener("keydown", (e: KeyboardEvent) => {
  if (e.ctrlKey && e.key.toLowerCase() === "q") {
    if (currentHoveredLink) {
      openSandboxBrowser(currentHoveredLink.href);
    } else {
      openSandboxBrowser();
    }
  }
});

export async function openSandboxBrowser(
  initialUrl?: string | null
): Promise<void> {
  toggles = await fetchToggles();
  if (!toggles.sandboxEnabled) return;
  const url = initialUrl || "about:blank";
  let container = document.getElementById("sandbox-browser");
  if (container) {
    const iframe = container.querySelector(
      ".sandbox-iframe"
    ) as HTMLIFrameElement;
    if (iframe) iframe.src = url;
    container.style.display = "flex";
    return;
  }

  const header = document.createElement("div");
  header.className = "sandbox-header";

  const addressBar = document.createElement("input");
  addressBar.type = "text";
  addressBar.className = "sandbox-url";
  addressBar.value = url;

  // Add close button
  const closeBtn = document.createElement("button");
  closeBtn.className = "sandbox-close-btn";
  closeBtn.innerText = "×";
  closeBtn.title = "Close";
  closeBtn.onclick = () => {
    container?.remove();
    document.removeEventListener("keydown", closeOnEsc);
  };

  const iframe = document.createElement("iframe");
  iframe.src = url;
  iframe.className = "sandbox-iframe";
  iframe.setAttribute(
    "sandbox",
    "allow-scripts allow-forms allow-popups allow-modals allow-presentation allow-same-origin"
  );
  iframe.setAttribute("referrerpolicy", "no-referrer");

  iframe.onload = () => {
    try {
      addressBar.value = iframe.contentWindow?.location.href || url;
    } catch {
      addressBar.value = url;
    }
  };

  addressBar.addEventListener("keydown", (e: KeyboardEvent) => {
    if (e.key === "Enter") {
      iframe.src = addressBar.value;
    }
  });

  const closeOnEsc = (e: KeyboardEvent) => {
    if (e.key === "Escape") {
      container?.remove();
      document.removeEventListener("keydown", closeOnEsc);
    }
  };
  document.addEventListener("keydown", closeOnEsc);

  header.appendChild(addressBar);
  header.appendChild(closeBtn);

  container = document.createElement("div");
  container.id = "sandbox-browser";
  container.appendChild(header);
  container.appendChild(iframe);
  document.body.appendChild(container);
}

interface PreviewPosition {
  x: number;
  y: number;
}

function getPreviewPosition(
  linkRect: DOMRect,
  previewWidth = 80,
  previewHeight = 120,
  clampMargin = 8 // Margin from all edges of the viewport
): PreviewPosition {
  let x = linkRect.left;
  let y = linkRect.bottom + clampMargin;

  const viewportWidth = window.innerWidth;
  const viewportHeight = window.innerHeight;

  // Clamp x so the preview stays inside the viewport with margin
  if (x + previewWidth > viewportWidth - clampMargin) {
    x = viewportWidth - previewWidth - clampMargin;
  }
  if (x < clampMargin) {
    x = clampMargin;
  }

  // Clamp y so the preview stays inside the viewport with margin
  if (y + previewHeight > viewportHeight - clampMargin) {
    // Try to show above the link if not enough space below
    y = linkRect.top - previewHeight - clampMargin;
    if (y < clampMargin) {
      y = viewportHeight - previewHeight - clampMargin; // Clamp to bottom if still out of view
      if (y < clampMargin) y = clampMargin; // Clamp to top if still out of view
    }
  }

  return { x, y };
}

export async function fetchMLResult(url: string): Promise<SecurityInfo> {
  try {
    console.log("Sending ML prediction request for URL:", url);
    const response = await fetch(
      `http://localhost:5000/predict`,
      {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url }),
      }
    );
    if (!response.ok) throw new Error("ML prediction failed");
    const data = await response.json();

    // Log the complete response
    console.log("ML Prediction Raw Response:", {
      fullResponse: data,
      prediction: data.prediction,
      confidence: data.confidence,
      additionalData: { ...data },
    });

    return {
      isSafe: data.prediction === "benign",
      mlCategory: data.prediction,
      confidence: data.confidence,
    };
  } catch (error) {
    console.warn("ML safety check failed:", error);
    return { isSafe: null };
  }
}

// Transaction simulation function for Web3 transactions
export async function simulateTransaction(transactionData: {
  from: string;
  to: string;
  value: string;
  data: string;
  gasLimit: number;
}): Promise<any> {
  try {
    console.log("Sending transaction simulation request:", transactionData);
    const response = await fetch("http://localhost:5000/simulate", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(transactionData),
    });
    if (!response.ok) throw new Error("Transaction simulation failed");
    const data = await response.json();
    console.log("Transaction simulation result:", data);
    return data;
  } catch (error) {
    console.warn("Transaction simulation failed:", error);
    throw error;
  }
}

chrome.runtime.onMessage.addListener((message) => {
  if (message.type === "OPEN_SANDBOX" && message.url) {
    openSandboxBrowser(message.url);
  }
});
