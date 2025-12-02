/**
 * Background script for CryptoC Chrome extension
 * Handles URL analysis, transaction simulation, metadata fetching, and redirect checking.
 */

import { parse } from "node-html-parser";

// Store toggle states in chrome.storage.local
function setToggleState(key: string, value: boolean) {
  chrome.storage.local.set({ [key]: value });
}

function getToggleState(key: string): Promise<boolean> {
  return new Promise((resolve) => {
    chrome.storage.local.get([key], (result) => {
      resolve(result[key] !== false); // default to true
    });
  });
}

// Listen for messages from content scripts or popup
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  // Handle metadata fetching for a given URL
  if (message.type === "FETCH_METADATA" && message.url) {
    fetchMetadata(message.url).then(sendResponse);
    return true; // Keep the message channel open for async response
  }

  // Handle WHOIS lookup
  if (message.type === "WHOIS_LOOKUP" && message.url) {
    getToggleState("whoisEnabled").then((enabled) => {
      if (enabled) {
        fetchWhoisInfo(message.url).then(sendResponse);
      } else {
        sendResponse(null);
      }
    });
    return true;
  }

  // Handle CRYPTOC_SEARCH message
  if (message.type === "CRYPTOC_SEARCH" && message.query && sender.tab) {
    const tabId = sender.tab.id;
    if (typeof tabId === "number") {
      getToggleState("searchEnabled").then((enabled) => {
        if (enabled) {
          const searchUrl =
            "https://www.google.com/search?q=" +
            encodeURIComponent(message.query);
          chrome.tabs.sendMessage(tabId, {
            type: "OPEN_SANDBOX",
            url: searchUrl,
          });
        }
      });
      return true;
    }
  }

  // Handle OPEN_SANDBOX message
  if (message.type === "OPEN_SANDBOX" && message.url && sender.tab) {
    const tabId = sender.tab.id;
    if (typeof tabId === "number") {
      getToggleState("sandboxEnabled").then((enabled) => {
        if (enabled) {
          chrome.tabs.sendMessage(tabId, {
            type: "OPEN_SANDBOX",
            url: message.url,
          });
        }
      });
      return true;
    }
  }

  // Listen for toggle state changes from the popup
  if (message.type === "TOGGLE_WHOIS") {
    setToggleState("whoisEnabled", message.enabled);
  }

  if (message.type === "TOGGLE_PHISHING") {
    setToggleState("phishingEnabled", message.enabled);
  }

  if (message.type === "TOGGLE_SANDBOX") {
    setToggleState("sandboxEnabled", message.enabled);
  }

  if (message.type === "TOGGLE_SEARCH") {
    setToggleState("searchEnabled", message.enabled);
  }

  async function fetchMetadata(url: string): Promise<{
    title: string;
    description: string;
    favicon: string;
  }> {
    try {
      const res = await fetch(url);
      const html = await res.text();
      const doc = parse(html);

      const title = doc.querySelector("title")?.textContent || "";
      const description =
        doc
          .querySelector('meta[name="description"]')
          ?.getAttribute("content") || "";
      const faviconRaw =
        doc.querySelector('link[rel~="icon"]')?.getAttribute("href") ||
        "/favicon.ico";

      const favicon = new URL(faviconRaw, url).href;

      return {
        title,
        description,
        favicon,
      };
    } catch (err) {
      console.error("Metadata fetch failed:", err);
      throw err;
    }
  }

  // Analyze a link for security and content type
  if (message.type === "ANALYZE_LINK" && message.url) {
    getToggleState("phishingEnabled").then((enabled) => {
      if (enabled) {
        analyzeLink(message.url, sender.tab?.url || "").then(sendResponse);
      } else {
        sendResponse({ isSafe: null });
      }
    });
    return true;
  }

  // Handle transaction simulation
  if (message.type === "SIMULATE_TRANSACTION" && message.transactionData) {
    simulateTransaction(message.transactionData).then(sendResponse).catch((error) => {
      sendResponse({ error: error.message });
    });
    return true;
  }
});

/**
 * Analyzes a URL for security and content characteristics
 * @param {string} url - The URL to analyze
 * @returns {Promise<{isHttps: boolean, isRedirect: boolean, isDownload: boolean}>}
 * Object containing analysis results:
 * - isHttps: Whether the URL uses HTTPS
 * - isRedirect: Whether the URL redirects to another location
 * - isDownload: Whether the URL points to a downloadable file
 */

async function analyzeLink(
  url: string,
  currentTabUrl: string
): Promise<{
  isHttps: boolean;
  isRedirect: boolean;
  finalHostname: string;
  originalHostname: string;
  isDownload: boolean;
  isSafe: boolean | null;
  mlCategory?: string;
}> {
  try {
    const [isHttps, redirectCheck, downloadCheck] = await Promise.all([
      Promise.resolve(checkProtocol(url)),
      checkRedirect(url, currentTabUrl),
      checkDownloadable(url),
    ]);

    return {
      isHttps,
      isRedirect: redirectCheck.isRedirect,
      finalHostname: redirectCheck.finalHostname,
      originalHostname: redirectCheck.originalHostname,
      isDownload: downloadCheck,
      isSafe: null,
    };
  } catch (error) {
    console.warn("Link analysis failed:", error);
    throw error;
  }
}

/**
 * Checks if a URL uses HTTPS protocol
 * @param {string} url - The URL to check
 * @returns {boolean} Whether the URL uses HTTPS
 */
function checkProtocol(url: string): boolean {
  return url.startsWith("https://");
}

/**
 * Checks if a URL redirects to another location
 * @param {string} url - The URL to check
 * @returns {Promise<{isRedirect: boolean, finalUrl: string}>}
 */
async function checkRedirect(
  url: string,
  currentTabUrl: string
): Promise<{
  isRedirect: boolean;
  finalHostname: string;
  originalHostname: string;
}> {
  try {
    const originalUrl = new URL(currentTabUrl);
    const originalHostname = originalUrl.hostname;

    // Follow redirects to get final URL
    const response = await fetch(url, {
      method: "HEAD",
      redirect: "follow", // follow chain redirects
    });

    const finalUrl = response.url;
    const finalUrlObj = new URL(finalUrl);
    const isRedirect = finalUrlObj.hostname !== originalHostname;

    return {
      isRedirect,
      finalHostname: finalUrlObj.hostname,
      originalHostname: originalHostname,
    };
  } catch (error) {
    console.error("Redirect analysis failed:", error);
    throw error;
  }
}

async function checkDownloadable(url: string): Promise<boolean> {
  try {
    const response = await fetch(url, {
      method: "HEAD",
    });

    const contentType = response.headers.get("content-type") || "";
    const contentDisposition =
      response.headers.get("content-disposition") || "";

    const riskyTypes = [
      "application/octet-stream",
      "application/x-msdownload",
      "application/x-executable",
      "application/x-zip-compressed",
      "application/pdf",
      "application/x-rar-compressed",
    ];

    const isAttachment = contentDisposition
      .toLowerCase()
      .includes("attachment");
    const isFile = riskyTypes.some((type) => contentType.startsWith(type));

    return isAttachment || isFile;
  } catch (error) {
    console.warn("Downloadable check failed:", error);
    return false;
  }
}

async function fetchWhoisInfo(url: string): Promise<any> {
  try {
    const response = await fetch("http://localhost:5000/whois", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ url }),
    });

    if (!response.ok) {
      console.error("WHOIS lookup failed:", response.statusText);
      return null;
    }

    const data = await response.json();
    console.log("WHOIS data received:", data);
    return data;
  } catch (error) {
    console.error("WHOIS lookup failed:", error);
    return null;
  }
}

chrome.runtime.onInstalled.addListener(() => {
  chrome.contextMenus.create({
    id: "searchWithCryptoC",
    title: "Search with CryptoC",
    contexts: ["selection"],
  });
});

chrome.contextMenus.onClicked.addListener((info, tab) => {
  if (info.menuItemId === "searchWithCryptoC" && info.selectionText) {
    chrome.tabs.sendMessage(tab?.id || 0, {
      type: "OPEN_SANDBOX",
      url:
        "https://www.google.com/search?q=" +
        encodeURIComponent(info.selectionText),
    });
  }
});

// Transaction simulation function for Web3 transactions
async function simulateTransaction(transactionData: {
  from: string;
  to: string;
  value: string;
  data: string;
  gasLimit: number;
}): Promise<any> {
  try {
    const response = await fetch("http://localhost:5000/simulate", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(transactionData),
    });
    if (!response.ok) throw new Error("Transaction simulation failed");
    return await response.json();
  } catch (error) {
    console.error("Transaction simulation failed:", error);
    throw error;
  }
}
