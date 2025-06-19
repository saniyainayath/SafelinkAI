document.addEventListener("DOMContentLoaded", function () {
    document.getElementById("closeBtn").addEventListener("click", function () {
        window.close();
    });

    const proceedBtn = document.getElementById("proceedBtn");
    if (proceedBtn) {
        proceedBtn.addEventListener("click", function () {
            // Get the original blocked URL from the query string
            const params = new URLSearchParams(window.location.search);
            const blockedUrl = params.get("blocked");
            if (blockedUrl) {
                window.location.href = blockedUrl;
            } else {
                alert("Original URL not found.");
            }
        });
    }
});
