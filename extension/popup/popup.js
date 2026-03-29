const ext = globalThis.browser ?? globalThis.chrome;
let analysisInProgress = false;

document.addEventListener("DOMContentLoaded", async () => {
    if (analysisInProgress) {
        return;
    }
    analysisInProgress = true;

    const riskPill = document.querySelector(".risk-pill");
    const riskList = document.querySelector(".risk-list");
    const riskyLinksList = document.getElementById("risky-links");
    const explanation = document.getElementById("explanation");
    const oauthStatus = document.getElementById("oauth-status");
    const safeBtn = document.getElementById("safe-btn");
    const reportBtn = document.getElementById("report-btn");
    const learnMoreBtn = document.getElementById("learn-more-btn");
    const learnMoreLink = document.getElementById("learn-more-link");
    const actionStatus = document.getElementById("action-status");
    let lastAnalysisContext = null;

    function updateUI(riskLevel, debug = {}) {

        riskList.innerHTML = "";
        renderRiskyLinks(debug);

        const reasons = deriveRiskReasons(riskLevel, debug);
        reasons.forEach(addRisk);
        explanation.textContent = buildExplanation(riskLevel, debug, reasons);

        if (riskLevel === "HIGH") {

            riskPill.textContent = "HIGH RISK";
            riskPill.style.background = "#e74c3c";

        } else if (riskLevel === "MEDIUM") {

            riskPill.textContent = "MEDIUM RISK";
            riskPill.style.background = "#f39c12";

        } else {

            riskPill.textContent = "SAFE";
            riskPill.style.background = "#2ecc71";
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

    function renderRiskyLinks(debug) {
        if (!riskyLinksList) {
            return;
        }
        riskyLinksList.innerHTML = "";

        const vtEvidence = Array.isArray(debug.vt_evidence) ? debug.vt_evidence : [];
        const riskyCandidates = vtEvidence
            .filter(item => {
                const stats = item?.stats || {};
                const malicious = Number(stats.malicious || 0);
                const suspicious = Number(stats.suspicious || 0);
                return malicious > 0 || suspicious > 0;
            })
            .map(item => item?.url)
            .filter(Boolean);

        const uniqueRisky = Array.from(new Set(riskyCandidates)).slice(0, 3);

        const analysisLinks = Array.isArray(lastAnalysisContext?.links) ? lastAnalysisContext.links : [];
        const visibleSuspiciousLinks = analysisLinks
            .filter(link => /^https?:\/\//i.test(String(link)))
            .slice(0, 3);

        if (uniqueRisky.length === 0 && Number(debug.url_score || 0) >= 0.82 && visibleSuspiciousLinks.length > 0) {
            visibleSuspiciousLinks.forEach((link) => {
                const item = document.createElement("li");
                item.textContent = link;
                riskyLinksList.appendChild(item);
            });
            return;
        }

        if (uniqueRisky.length === 0 && Number(debug.url_score || 0) >= 0.82) {
            const item = document.createElement("li");
            item.textContent = "High-risk URL detected (possible typo-spoof or phishing domain).";
            riskyLinksList.appendChild(item);
            return;
        }

        if (uniqueRisky.length === 0 && Number(debug.link_score || 0) >= 0.9) {
            const item = document.createElement("li");
            item.textContent = "Suspicious links detected, avoid clicking unknown URLs.";
            riskyLinksList.appendChild(item);
            return;
        }

        if (uniqueRisky.length === 0) {
            const item = document.createElement("li");
            item.textContent = "No risky links identified.";
            riskyLinksList.appendChild(item);
            return;
        }

        uniqueRisky.forEach((url) => {
            const item = document.createElement("li");
            item.textContent = url;
            riskyLinksList.appendChild(item);
        });
    }

    function buildExplanation(riskLevel, debug, reasons) {
        const attachmentRisk = Number(debug.attachment_score || 0) >= 0.45;
        const contentRisk = Number(debug.content_score || 0) >= 0.5 || Number(debug.text_ml_score || 0) >= 0.6;
        const urlRisk = Number(debug.url_score || 0) >= 0.82 || Number(debug.vt_score || 0) >= 0.85;

        if (riskLevel === "SAFE") {
            return "This email appears safe: no strong malicious URL, attachment, or content patterns were detected.";
        }

        const parts = [];
        if (urlRisk) {
            parts.push("risky or malicious link reputation");
        }
        if (attachmentRisk) {
            parts.push("suspicious attachment indicators");
        }
        if (contentRisk) {
            parts.push("phishing-like language patterns");
        }

        if (parts.length === 0) {
            return reasons[0] || "Suspicious behavior detected. Verify sender before acting.";
        }

        return `Email flagged due to ${parts.join(", ")}. Avoid clicking links or downloading files until verified.`;
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

    function setActionStatus(text, color = "#93c5fd") {
        if (!actionStatus) {
            return;
        }
        actionStatus.textContent = text;
        actionStatus.style.color = color;
    }

    function buildFingerprint(emailData) {
        const body = String(emailData?.body || "");
        const links = Array.isArray(emailData?.links) ? emailData.links : [];
        return btoa(unescape(encodeURIComponent(`${body.slice(0, 256)}|${links.join("|")}`))).slice(0, 80);
    }

    async function postFeedback(actionType) {
        if (!lastAnalysisContext) {
            setActionStatus("Analyze an email first", "#f59e0b");
            return;
        }
        try {
            const response = await fetch("http://127.0.0.1:8000/feedback", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({
                    action: actionType,
                    risk_level: lastAnalysisContext.riskLevel,
                    email_fingerprint: lastAnalysisContext.emailFingerprint,
                    url: lastAnalysisContext.primaryUrl,
                    message_id: lastAnalysisContext.messageId || null,
                    thread_id: lastAnalysisContext.threadId || null,
                    reasons: lastAnalysisContext.reasons || [],
                    attachment_count: lastAnalysisContext.attachmentCount || 0,
                    has_attachment_hash: Boolean(lastAnalysisContext.hasAttachmentHash),
                    debug: lastAnalysisContext.debug || {}
                })
            });
            if (!response.ok) {
                throw new Error(`feedback_failed_${response.status}`);
            }
            setActionStatus(
                actionType === "MARK_SAFE" ? "Marked as safe and feedback saved" : "Phishing report feedback saved",
                "#22c55e"
            );
        } catch (error) {
            console.warn("Feedback submit failed:", error);
            setActionStatus("Failed to save feedback", "#ef4444");
        }
    }

    safeBtn?.addEventListener("click", async () => {
        await postFeedback("MARK_SAFE");
    });

    reportBtn?.addEventListener("click", async () => {
        await postFeedback("REPORT_PHISHING");
        if (lastAnalysisContext?.messageId) {
            try {
                const spamResult = await ext.runtime.sendMessage({
                    type: "GMAIL_MOVE_TO_SPAM",
                    messageId: lastAnalysisContext.messageId
                });
                if (spamResult?.ok) {
                    setActionStatus("Reported and moved message to spam", "#22c55e");
                } else {
                    setActionStatus(`Reported, spam move failed (${spamResult?.error || "unknown"})`, "#f59e0b");
                }
            } catch (error) {
                console.warn("Gmail spam move messaging failed:", error);
                setActionStatus("Reported, spam move request failed", "#f59e0b");
            }
        } else {
            setActionStatus("Reported. Message ID unavailable for auto spam move", "#f59e0b");
        }
        try {
            const tabs = await ext.tabs.query({ active: true, currentWindow: true });
            const currentUrl = tabs?.[0]?.url || "https://mail.google.com/";
            const reportUrl = `https://mail.google.com/mail/u/0/#spam`;
            await ext.tabs.create({ url: reportUrl });
            console.log("Opened Gmail spam/report area from:", currentUrl);
        } catch (error) {
            console.warn("Unable to open Gmail report flow:", error);
        }
    });

    learnMoreBtn?.addEventListener("click", async () => {
        await ext.tabs.create({
            url: ext.runtime.getURL("pages/phishguard.html")
        });
    });

    learnMoreLink?.addEventListener("click", async (event) => {
        event.preventDefault();
        await ext.tabs.create({
            url: ext.runtime.getURL("pages/phishguard.html")
        });
    });

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
        const reasons = deriveRiskReasons(data.risk_level, data.debug || {});
        lastAnalysisContext = {
            riskLevel: data.risk_level,
            debug: data.debug || {},
            reasons,
            primaryUrl,
            links: emailData.links || [],
            messageId: emailData.message_id || null,
            threadId: emailData.thread_id || null,
            attachmentCount: mergedAttachments.length,
            hasAttachmentHash: mergedAttachments.some(item => Boolean(item.sha256)),
            emailFingerprint: buildFingerprint(emailData)
        };
        setActionStatus("Actions ready");

    } catch (error) {

        console.error("Extension Error:", error);

        riskPill.textContent = "ERROR";
        riskPill.style.background = "gray";
        explanation.textContent = "Could not analyze email.";
        riskList.innerHTML = "";
        setActionStatus("Analysis failed", "#ef4444");
    } finally {
        analysisInProgress = false;
    }

});
