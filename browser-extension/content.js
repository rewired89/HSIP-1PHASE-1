// Use Firefox 'browser' if available, otherwise Chrome-style 'chrome'
const ext = typeof browser !== "undefined" ? browser : chrome;

// LOUD: prove this script runs at all
console.log("[HSIP] content.js loaded on:", window.location.href);

// HSIP site detection is based on a simple marker:
//   <meta name="hsip-site" content="1">
const SUPPORTED_META_NAME = "hsip-site";

function isHsipSite() {
  const metas = document.querySelectorAll(
    "meta[name='" + SUPPORTED_META_NAME + "']"
  );
  return metas.length > 0;
}

async function handleHsipSite() {
  console.log("[HSIP] hsip-site meta detected on:", window.location.href);

  if (!ext || !ext.runtime || !ext.runtime.sendMessage) {
    console.warn("[HSIP] extension runtime not available on this page");
    return;
  }

  try {
    // Ask background script for a consent token
    const token = await ext.runtime
      .sendMessage({ type: "HSIP_GET_TOKEN" })
      .catch((e) => {
        console.warn("[HSIP] HSIP_GET_TOKEN error:", e);
        return null;
      });

    if (!token) {
      console.log("[HSIP] no token returned, skipping badge");
      return;
    }

    console.log(
      "[HSIP] got token (first 40 chars):",
      token.slice(0, 40) + "..."
    );

    // Expose token to page JS for HSIP-aware sites
    window.postMessage(
      { type: "HSIP_TOKEN", token },
      window.location.origin
    );

    // Show a small “Protected by HSIP” badge in the corner
    const badge = document.createElement("div");
    badge.textContent = "Protected by HSIP";
    badge.style.cssText = `
      position: fixed;
      bottom: 8px;
      right: 8px;
      padding: 4px 8px;
      background: #00c853;
      color: #fff;
      font-size: 11px;
      border-radius: 3px;
      z-index: 2147483647;
      font-family: sans-serif;
      box-shadow: 0 1px 3px rgba(0,0,0,0.3);
    `;
    document.body.appendChild(badge);
  } catch (e) {
    console.warn("[HSIP] content script error:", e);
  }
}

// Only activate on pages that explicitly opt-in to HSIP
if (isHsipSite()) {
  handleHsipSite();
} else {
  // For debugging, we log every page while we’re testing
  console.log("[HSIP] no hsip-site meta on:", window.location.href);
}
