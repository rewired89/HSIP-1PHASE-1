console.log("[HSIP popup] script loaded");

const btn = document.getElementById("btn");
const out = document.getElementById("out");

if (!btn || !out) {
  console.error("[HSIP popup] missing DOM elements");
} else {
  btn.addEventListener("click", async () => {
    out.textContent = "Requesting token from HSIP tray...";

    try {
      const res = await fetch("http://127.0.0.1:9389/consent", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          scopes: ["login", "hello"],
          aud: "browser-extension"
        })
      });

      console.log("[HSIP popup] fetch status", res.status);

      const json = await res.json();
      console.log("[HSIP popup] response JSON", json);

      if (json.token) {
        out.textContent = json.token;
      } else {
        out.textContent = "No token field. Raw: " + JSON.stringify(json);
      }
    } catch (e) {
      console.error("[HSIP popup] fetch error", e);
      out.textContent = "Error: " + e;
    }
  });
}
