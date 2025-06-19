document.addEventListener("DOMContentLoaded", function () {
    const checkBtn = document.getElementById("check-btn");
    const manualUrlInput = document.getElementById("manual-url");
    const urlDisplay = document.getElementById("url-display");
    const resultMessage = document.getElementById("result-message");
    const loadingBarContainer = document.getElementById("loading-bar-container");
    const loadingBar = document.getElementById("loading-bar");

    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
        if (tabs.length > 0) {
            const currentUrl = tabs[0].url;
            urlDisplay.textContent = currentUrl;
            checkBtn.disabled = false;
        }
    });
    checkBtn.addEventListener("click", async () => {
        const urlToCheck = urlDisplay.textContent || manualUrlInput.value;  

        if (urlToCheck) {
            await scanUrl(urlToCheck);  
        } else {
            resultMessage.innerHTML = "<p style='color: red;'>⚠️ Please enter a valid URL to scan.</p>";
        }
    });
    async function scanUrl(url) {
        checkBtn.disabled = true;
        resultMessage.innerHTML = "";
        loadingBarContainer.style.display = "block";
        loadingBar.style.width = "0%";
        setTimeout(() => { loadingBar.style.width = "80%"; }, 100);

        try {
            await sendUrlToServer(url);  
        } catch (error) {
            console.error("❌ Error checking the URL:", error);
            resultMessage.innerHTML = "<p style='color: red;'>⚠️ Error checking the URL. Please try again.</p>";
        }

        loadingBar.style.width = "100%";
        setTimeout(() => {
            loadingBarContainer.style.display = "none";
            checkBtn.disabled = false;
        }, 400);
    }
    async function sendUrlToServer(url) {
        try {
            const response = await fetch("http://127.0.0.1:5000/check_url", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ url, source: "popup" })
            });

            if (!response.ok) {
                throw new Error("Network error");
            }

            const data = await response.json();

            // Use the hybrid risk level and reasons from the backend
            const riskLevel = data.risk_level || "Unknown";
            const reasons = Array.isArray(data.reasons) ? data.reasons : [];

            chrome.storage.local.get("lastCheckedUrls", (storedData) => {
                let lastCheckedUrls = storedData.lastCheckedUrls || {};
                lastCheckedUrls[url] = { riskLevel, timestamp: Date.now(), reasons };
                chrome.storage.local.set({ lastCheckedUrls });
            });

            displayResult(riskLevel, reasons);

        } catch (error) {
            console.error("❌ Error in sendUrlToServer:", error);
            throw error;
        }
    }
chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
    if (tabs[0]?.id) {
        chrome.tabs.sendMessage(tabs[0].id, {
            action: "showBanner",
            type: result 
        }, (response) => {
            if (chrome.runtime.lastError) {
                console.warn("Could not send message to content script:", chrome.runtime.lastError.message);
            } else {
                console.log("Message sent to content script:", response);
            }
        });
    }
});
    function displayResult(riskLevel, reasons) {
        let color;
        if (riskLevel === "High") color = "red";
        else if (riskLevel === "Medium") color = "orange";
        else if (riskLevel === "Low") color = "green";
        else color = "gray";

        let reasonsHtml = "";
        if (reasons && reasons.length > 0) {
            reasonsHtml = "<ul style='margin: 0; padding-left: 18px;'>";
            reasons.forEach(reason => {
                reasonsHtml += `<li>${reason}</li>`;
            });
            reasonsHtml += "</ul>";
        }

        resultMessage.innerHTML = `
            <p style="color: ${color}; font-weight: bold;">
                🚨 Risk Level: ${riskLevel}
            </p>
            ${reasonsHtml}
        `;
    }

});
