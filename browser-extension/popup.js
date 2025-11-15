async function loadStatus() {
  const statusEl = document.getElementById("status");
  const detailsEl = document.getElementById("details");
  const peerEl = document.getElementById("peer");

  statusEl.textContent = "HSIP: Checking…";
  statusEl.className = "status-unknown";
  detailsEl.textContent = "";
  peerEl.textContent = "";

  try {
    const res = await fetch("http://127.0.0.1:9389/status");
    const data = await res.json();

    const threat = data.threat_level || "green";

    if (data.ok && threat === "green") {
      statusEl.textContent = "HSIP Good";
      statusEl.className = "status-good";
      detailsEl.textContent = "HSIP is running and protecting this browser.";
    } else if (data.ok && threat === "red") {
      statusEl.textContent = "HSIP Danger";
      statusEl.className = "status-danger";
      detailsEl.textContent =
        "HSIP detected a serious risk. Avoid entering personal data.";
    } else {
      statusEl.textContent = "HSIP Bad";
      statusEl.className = "status-bad";
      detailsEl.textContent = "HSIP is installed but not fully active.";
    }

    if (data.peer) {
      const shortPeer =
        data.peer.length > 12
          ? data.peer.slice(0, 6) + "…" + data.peer.slice(-4)
          : data.peer;
      peerEl.textContent = "Device identity: " + shortPeer;
    }
  } catch (e) {
    statusEl.textContent = "HSIP Bad";
    statusEl.className = "status-bad";
    detailsEl.textContent =
      "HSIP is not running. Open the HSIP app to enable protection.";
  }
}

document.getElementById("refresh").addEventListener("click", loadStatus);
loadStatus();
