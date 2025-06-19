document.addEventListener('DOMContentLoaded', () => {
    const form = document.getElementById('urlForm');
    const input = document.getElementById('url-input');
    const resultContainer = document.getElementById('result-container');
    const resultMessage = document.getElementById('result-message');
    const loadingBarContainer = document.getElementById('loading-bar-container');
    const loadingBar = document.getElementById('loading-bar');
    const vtSection = document.getElementById('vt-result');
    const vtLegend = document.getElementById('vt-legend');
    const riskBox = document.getElementById('risk-level-box');
    const checkBtn = document.getElementById('check-btn');

    form.addEventListener('submit', async (e) => {
        e.preventDefault();

        const url = input.value.trim();
        if (!url) return;

        // Reset
        resultContainer.style.display = 'none';
        resultMessage.textContent = '';
        loadingBarContainer.style.display = 'block';
        loadingBar.style.width = '0%';
        vtSection.style.display = 'none';
        vtLegend.innerHTML = '';

        setTimeout(() => { loadingBar.style.width = '80%'; }, 100);

        try {
            const response = await fetch('/check_url', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ url })
            });

            const data = await response.json();
            console.log('VirusTotal:', data.virustotal);

            loadingBar.style.width = '100%';
            setTimeout(() => { loadingBarContainer.style.display = 'none'; }, 400);
            resultContainer.style.display = 'block';

            // Show risk level at the top
            if (data.risk_level) {
                let riskClass = '';
                if (data.risk_level.toLowerCase() === 'low') riskClass = 'risk-low';
                else if (data.risk_level.toLowerCase() === 'medium') riskClass = 'risk-medium';
                else riskClass = 'risk-high';

                riskBox.className = `risk-level-box ${riskClass}`;
                riskBox.textContent = `Risk Level: ${data.risk_level.charAt(0).toUpperCase() + data.risk_level.slice(1)}`;
                riskBox.style.display = 'block';
                checkBtn.style.display = 'none';
            } else {
                riskBox.style.display = 'none';
                checkBtn.style.display = 'inline-block';
            }

            // ML result
            document.getElementById('ml-result').innerHTML = `<p><strong>ML Prediction:</strong> ${data.ml_result || 'N/A'}</p>`;

            // GSB result
            document.getElementById('gsb-result').innerHTML = `<p><strong>Google Safe Browsing:</strong> ${data.google_safe_browsing || 'N/A'}</p>`;
            
            // VirusTotal result
            if (data.virustotal && typeof data.virustotal === "object" && !data.virustotal.error) {
                vtSection.style.display = 'block';
                createVTPieChart(data.virustotal); // This should set vtLegend.innerHTML
            } else {
                vtSection.style.display = 'none';
            }
            // WHOIS info
            const whoisDiv = document.getElementById('whois-info');
            if (data.whois && typeof data.whois === "object" && !Array.isArray(data.whois)) {
                // Handle arrays in WHOIS fields (show first value)
                function getFirst(val) {
                    if (Array.isArray(val)) return val[0];
                    return val || 'N/A';
                }
                whoisDiv.innerHTML = `
                    <table class="whois-table">
                        <tr><th>Domain</th><td>${getFirst(data.whois.domain_name)?.toLowerCase() || 'N/A'}</td></tr>
                        <tr><th>Registrar</th><td>${getFirst(data.whois.registrar) || 'N/A'}</td></tr>
                        <tr><th>Creation Date</th><td>${new Date(getFirst(data.whois.creation_date)).toLocaleString() || 'N/A'}</td></tr>
                        <tr><th>Expiration Date</th><td>${new Date(getFirst(data.whois.expiration_date)).toLocaleString() || 'N/A'}</td></tr>
                    </table>
                `;
            } else if (typeof data.whois === "string") {
                whoisDiv.innerHTML = `<p>${data.whois}</p>`;
            } else {
                whoisDiv.innerHTML = `<p>WHOIS data not available.</p>`;
            }

        } catch (error) {
            loadingBarContainer.style.display = 'none';
            resultMessage.className = 'result-message malicious';
            resultContainer.style.display = 'block';
        }
    });

    input.addEventListener('input', () => {
        resultContainer.style.display = 'none';
        riskBox.style.display = 'none';
        checkBtn.style.display = 'inline-block';
        // Optionally clear old results:
        resultMessage.textContent = '';
        document.getElementById('ml-result').innerHTML = '';
        document.getElementById('gsb-result').innerHTML = '';
        vtSection.style.display = 'none';
        vtLegend.innerHTML = '';
        document.getElementById('whois-info').innerHTML = '';
    });

    function createVTPieChart(stats) {
        const ctx = document.getElementById('vt-piechart').getContext('2d');

        const chartData = {
            labels: ['Harmless', 'Malicious', 'Suspicious'],
            datasets: [{
                data: [
                    stats.harmless || 0,
                    stats.malicious || 0,
                    stats.suspicious || 0
                ],
                backgroundColor: ['#00ff99', '#ff0055', '#ffcc00'],
                borderColor: '#111',
                borderWidth: 2
            }]
        };

        new Chart(ctx, {
            type: 'pie',
            data: chartData,
            options: {
                responsive: false,
                plugins: {
                    legend: { display: false }
                }
            }
        });
        // Custom legend
        vtLegend.innerHTML = `
            <p><span style="color:#00ff99;">●</span> Harmless: ${stats.harmless || 0}</p>
            <p><span style="color:#ffcc00;">●</span> Suspicious: ${stats.suspicious || 0}</p>
            <p><span style="color:#ff0055;">●</span> Malicious: ${stats.malicious || 0}</p>
        `;
    }
    // Toggle sidebar
    const sidebarToggle = document.getElementById('sidebar-toggle');
    const sidebar = document.getElementById('sidebar');
    if (sidebarToggle && sidebar) {
        sidebarToggle.addEventListener('click', function() {
            sidebar.classList.toggle('active');
        });
    }

    const messageForm = document.getElementById('messageForm');
    const messageInput = document.getElementById('message-input');
    const messageResult = document.getElementById('message-result');

    if (messageForm) {
        messageForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            const message = messageInput.value.trim();
            if (!message) return;
            messageResult.style.display = 'block';
            messageResult.innerHTML = '<em>Checking...</em>';

            try {
                const response = await fetch('/check_message', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ message })
                });
                const data = await response.json();
                let statusHtml, statusIcon;

                if (data.suspicious) {
                    statusHtml = `<strong>Status:</strong> ⚠️ Suspicious`;
                    statusIcon = "malicious";
                } else {
                    statusHtml = `<strong>Status:</strong> ✅ Safe`;
                    statusIcon = "safe";
                }

                messageResult.innerHTML = `
                    <h3>Message Analysis</h3>
                    <p>${statusHtml}</p>
                    <p><strong>Reason:</strong> ${data.reason}</p>
                    <p><strong>Links Detected:</strong> ${data.links && data.links.length ? data.links.join(', ') : 'None'}</p>
                `;
            } catch (error) {
                messageResult.innerHTML = '<span style="color:red;">Error checking message.</span>';
                messageResult.style.display = 'block';
            }
        });

        // Hide result on input change
        messageInput.addEventListener('input', () => {
            messageResult.innerHTML = '';
            messageResult.style.display = 'none';
        });
    }

    // --- Tab logic for remembering active tab ---
    function showTab(tab) {
        document.getElementById('tab-link').style.display = (tab === 'link') ? 'block' : 'none';
        document.getElementById('tab-message').style.display = (tab === 'message') ? 'block' : 'none';
        document.getElementById('tab-link-btn').classList.toggle('active', tab === 'link');
        document.getElementById('tab-message-btn').classList.toggle('active', tab === 'message');
        // Remember the last active tab
        localStorage.setItem('safelinkai-active-tab', tab);
    }

    // Attach tab button events
    const tabLinkBtn = document.getElementById('tab-link-btn');
    const tabMessageBtn = document.getElementById('tab-message-btn');

    if (tabLinkBtn) tabLinkBtn.addEventListener('click', () => showTab('link'));
    if (tabMessageBtn) tabMessageBtn.addEventListener('click', () => showTab('message'));

    // On page load, restore last active tab (default to 'link')
    const lastTab = localStorage.getItem('safelinkai-active-tab');
    if (lastTab === 'message') {
        showTab('message');
    } else {
        showTab('link');
    }
});
