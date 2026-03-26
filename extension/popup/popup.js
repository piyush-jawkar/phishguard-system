const ext = globalThis.browser ?? globalThis.chrome;
let analysisInProgress = false;

document.addEventListener("DOMContentLoaded", async () => {
    if (analysisInProgress) {
        return;
    }
    analysisInProgress = true;

    const riskPill = document.querySelector(".risk-pill");
    const riskList = document.querySelector(".risk-list");
    const explanation = document.getElementById("explanation");

    function updateUI(riskLevel) {

        riskList.innerHTML = "";

        if (riskLevel === "HIGH") {

            riskPill.textContent = "HIGH RISK";
            riskPill.style.background = "#e74c3c";

            addRisk("Malicious indicators detected");
            addRisk("Suspicious links found");

            explanation.textContent =
                "This email contains strong phishing indicators.";

        } else if (riskLevel === "MEDIUM") {

            riskPill.textContent = "MEDIUM RISK";
            riskPill.style.background = "#f39c12";

            addRisk("Some suspicious behaviour detected");

            explanation.textContent =
                "Exercise caution. Verify sender before clicking links.";

        } else {

            riskPill.textContent = "SAFE";
            riskPill.style.background = "#2ecc71";

            addRisk("No phishing indicators detected");

            explanation.textContent =
                "No suspicious patterns detected in this email.";
        }
    }

    function addRisk(text) {
        const li = document.createElement("li");
        li.textContent = text;
        riskList.appendChild(li);
    }

    async function getEmailData(tabId) {
        try {
            return await ext.tabs.sendMessage(tabId, { type: "EXTRACT_EMAIL" });
        } catch (error) {
            const canInject = Boolean(ext.scripting?.executeScript);
            const isMissingReceiver =
                String(error?.message || "").includes("Receiving end does not exist");

            if (!canInject || !isMissingReceiver) {
                throw error;
            }

            await ext.scripting.executeScript({
                target: { tabId },
                files: ["scripts/content.js"]
            });

            return await ext.tabs.sendMessage(tabId, { type: "EXTRACT_EMAIL" });
        }
    }

    try {

        const tabs = await ext.tabs.query({ active: true, currentWindow: true });

        // 🔥 Request email content from content script
        const emailData = await getEmailData(tabs[0].id);

        if (!emailData || !emailData.body) {
            throw new Error("No email content extracted");
        }

        // 🔥 Determine PRIMARY suspicious URL
        let primaryUrl = "";

        if (emailData.links && emailData.links.length > 0) {
            primaryUrl = emailData.links[0];  // First real link inside email
        } else {
            primaryUrl = "";  // No links case
        }

        const apiResponse = await fetch("http://127.0.0.1:8000/analyze-email", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                url: primaryUrl,
                body: emailData.body,
                links: emailData.links || []
            })
        });

        if (!apiResponse.ok) throw new Error("Backend error");

        const data = await apiResponse.json();

        updateUI(data.risk_level);

    } catch (error) {

        console.error("Extension Error:", error);

        riskPill.textContent = "ERROR";
        riskPill.style.background = "gray";
        explanation.textContent = "Could not analyze email.";
        riskList.innerHTML = "";
    } finally {
        analysisInProgress = false;
    }

});
