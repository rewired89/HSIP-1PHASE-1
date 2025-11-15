console.log("[HSIP] background loaded");

// Periodic status ping (for your own debugging, not shown to users)
async function pingStatus() {
  try {
    const res = await fetch("http://127.0.0.1:9389/status");
    const data = await res.json();
    console.log("[HSIP] status:", data);
  } catch (e) {
    console.warn("[HSIP] status error:", e);
  }
}

// Run once and then every 30s
pingStatus();
setInterval(pingStatus, 30000);

// Handle messages from content scripts / popup
browser.runtime.onMessage.addListener((msg, sender) => {
  if (msg.type === "HSIP_GET_TOKEN") {
    return (async () => {
      try {
        const res = await fetch("http://127.0.0.1:9389/consent", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            scopes: ["login", "hello"],
            aud: "browser-extension"
          })
        });
        const data = await res.json();
        return data.token || null;
      } catch (e) {
        console.warn("[HSIP] token error:", e);
        return null;
      }
    })();
  }
});
