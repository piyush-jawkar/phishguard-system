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
    const oauthStatus = document.getElementById("oauth-status");

    function updateUI(riskLevel, debug = {}) {

        riskList.innerHTML = "";

        const reasons = deriveRiskReasons(riskLevel, debug);
        reasons.forEach(addRisk);

        if (riskLevel === "HIGH") {

            riskPill.textContent = "HIGH RISK";
            riskPill.style.background = "#e74c3c";

            explanation.textContent =
                reasons[0] || "This email contains strong phishing indicators.";

        } else if (riskLevel === "MEDIUM") {

            riskPill.textContent = "MEDIUM RISK";
            riskPill.style.background = "#f39c12";

            explanation.textContent =
                reasons[0] || "Exercise caution. Verify sender before clicking links.";

        } else {

            riskPill.textContent = "SAFE";
            riskPill.style.background = "#2ecc71";

            explanation.textContent =
                reasons[0] || "No suspicious patterns detected in this email.";
        }
    }

    function addRisk(text) {
        const li = document.createElement("li");
        li.textContent = text;
        riskList.appendChild(li);
    }

    function deriveRiskReasons(riskLevel, debug) {
        const reasons = [];
        const vtEvidence = Array.isArray(debug.vt_evidence) ? debug.vt_evidence : [];
        const attachmentEvidence = Array.isArray(debug.attachment_evidence) ? debug.attachment_evidence : [];
        const attachmentVtEvidence = Array.isArray(debug.attachment_vt_evidence) ? debug.attachment_vt_evidence : [];

        const vtUrlMalicious = vtEvidence.some(item => Number(item?.stats?.malicious || 0) > 0);
        const vtAttachmentMalicious = attachmentVtEvidence.some(
            item => Number(item?.stats?.malicious || 0) > 0 || Number(item?.stats?.suspicious || 0) > 0
        );
        const suspiciousAttachment = attachmentEvidence.some(item => Number(item?.score || 0) >= 0.45);
        const urlHigh = Number(debug.url_score || 0) >= 0.82;
        const linkHigh = Number(debug.link_score || 0) >= 0.9;
        const brandSpoof = Number(debug.brand_spoof_score || 0) >= 0.95;

        if (vtAttachmentMalicious) {
            reasons.push("Malicious attachment hash detected");
        }
        if (suspiciousAttachment) {
            reasons.push("Suspicious attachment type or filename detected");
        }
        if (vtUrlMalicious) {
            reasons.push("Malicious URL reputation found");
        }
        if (urlHigh || linkHigh) {
            reasons.push("Suspicious link behavior detected");
        }
        if (brandSpoof) {
            reasons.push("Possible brand spoofing detected");
        }

        if (reasons.length === 0) {
            if (riskLevel === "HIGH") {
                reasons.push("Multiple phishing indicators detected");
            } else if (riskLevel === "MEDIUM") {
                reasons.push("Some suspicious behavior detected");
            } else {
                reasons.push("No phishing indicators detected");
            }
        }

        return reasons.slice(0, 4);
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

    async function testGmailOAuth() {
        try {
            const authResult = await ext.runtime.sendMessage({ type: "GMAIL_AUTH_TEST" });
            if (!authResult?.ok) {
                console.warn("Gmail OAuth test failed:", authResult?.error || "unknown");
                if (oauthStatus) {
                    oauthStatus.textContent = `Gmail OAuth: failed (${authResult?.error || "unknown"})`;
                    oauthStatus.style.color = "#e74c3c";
                }
            } else {
                console.log("Gmail OAuth test ok:", authResult.profile?.emailAddress || "unknown");
                if (oauthStatus) {
                    oauthStatus.textContent = `Gmail OAuth: connected (${authResult.profile?.emailAddress || "unknown"})`;
                    oauthStatus.style.color = "#2ecc71";
                }
            }
        } catch (error) {
            console.warn("Gmail OAuth messaging failed:", error);
            if (oauthStatus) {
                oauthStatus.textContent = `Gmail OAuth: messaging error (${String(error?.message || error)})`;
                oauthStatus.style.color = "#e74c3c";
            }
        }
    }

    async function getAttachmentHashesFromGmail(messageId) {
        if (!messageId) {
            return [];
        }
        try {
            const hashResult = await ext.runtime.sendMessage({
                type: "GMAIL_GET_ATTACHMENT_HASHES",
                messageId
            });
            if (!hashResult?.ok) {
                console.warn("Gmail attachment hash fetch failed:", hashResult?.error || "unknown");
                return [];
            }
            return hashResult.attachments || [];
        } catch (error) {
            console.warn("Gmail attachment hash messaging failed:", error);
            return [];
        }
    }

    try {
        await testGmailOAuth();

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

        const gmailAttachmentHashes = await getAttachmentHashesFromGmail(emailData.message_id);
        console.log("[PhishGuard][Popup] Gmail message context:", {
            message_id: emailData.message_id || null,
            thread_id: emailData.thread_id || null
        });
        console.log("[PhishGuard][Popup] Attachment hash fetch summary:", {
            dom_attachments: (emailData.attachments || []).length,
            gmail_hashed_attachments: gmailAttachmentHashes.filter(item => item.sha256).length,
            gmail_total_attachments: gmailAttachmentHashes.length
        });
        const fallbackDomAttachments = (emailData.attachments || []).map(item => ({
            filename: item.filename
        }));
        const attachmentByName = new Map();
        for (const item of fallbackDomAttachments) {
            attachmentByName.set(String(item.filename || "").toLowerCase(), item);
        }
        for (const item of gmailAttachmentHashes) {
            const key = String(item.filename || "").toLowerCase();
            attachmentByName.set(key, {
                filename: item.filename,
                content_type: item.content_type || "",
                sha256: item.sha256 || ""
            });
        }
        const mergedAttachments = Array.from(attachmentByName.values()).filter(item => item.filename);
        console.log(
            "[PhishGuard][Popup] Backend attachment payload:",
            mergedAttachments.map(item => ({
                filename: item.filename,
                has_sha256: Boolean(item.sha256),
                content_type: item.content_type || null
            }))
        );

        const apiResponse = await fetch("http://127.0.0.1:8000/analyze-email", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                url: primaryUrl,
                body: emailData.body,
                links: emailData.links || [],
                attachments: mergedAttachments
            })
        });

        if (!apiResponse.ok) throw new Error("Backend error");

        const data = await apiResponse.json();

        updateUI(data.risk_level, data.debug || {});

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
