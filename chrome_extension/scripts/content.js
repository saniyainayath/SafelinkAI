chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (message.action === "showBanner") {
        console.log(" Injecting security warning banner...");
        if (!document.body) {
            console.warn("waiting for document body to load...");
            let observer = new MutationObserver(() => {
                if (document.body) {
                    observer.disconnect();
                    injectBanner(message);
                }
            });
            observer.observe(document, { childList: true, subtree: true });
            return;
        }
        injectBanner(message);
    }
});

function injectBanner(message) {
    let oldBanner = document.getElementById("security-warning-banner");
    if (oldBanner) oldBanner.remove();
    let banner = document.createElement("div");
    banner.id = "security-warning-banner";
    banner.style.position = "fixed";
    banner.style.top = "0";
    banner.style.left = "0";
    banner.style.width = "100%";
    banner.style.padding = "12px";
    banner.style.backgroundColor = message.type === "malicious"
        ? "#142d19" // dark greenish for malicious
        : "#16243a"; // dark blue for suspicious
    banner.style.color = message.type === "malicious"
        ? "#00ff99"
        : "#00c3ff";
    banner.style.textAlign = "center";
    banner.style.fontSize = "16px";
    banner.style.fontWeight = "bold";
    banner.style.zIndex = "99999";
    banner.style.boxShadow = "0 2px 12px #00ff9955";
    banner.style.letterSpacing = "0.5px";
    banner.innerHTML = message.type === "malicious"
        ? "🚨 WARNING: This site is malicious! Proceed with extreme caution!"
        : "⚠️ WARNING: This site is suspicious. Be careful when entering any information.";

    let closeButton = document.createElement("button");
    closeButton.innerText = "✖";
    closeButton.style.marginLeft = "15px";
    closeButton.style.border = "none";
    closeButton.style.background = "transparent";
    closeButton.style.color = banner.style.color;
    closeButton.style.fontSize = "16px";
    closeButton.style.cursor = "pointer";
    closeButton.onclick = () => banner.remove();
    banner.appendChild(closeButton);

    document.body.prepend(banner);
}
