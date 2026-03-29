const ext = globalThis.browser ?? globalThis.chrome;
console.log("[PhishGuard][BG] Service worker started");

function getAuthTokenInteractive() {
    return new Promise((resolve, reject) => {
        ext.identity.getAuthToken({ interactive: true }, (token) => {
            const err = ext.runtime.lastError;
            if (err) {
                reject(new Error(err.message));
                return;
            }
            if (!token) {
                reject(new Error("No OAuth token returned"));
                return;
            }
            resolve(token);
        });
    });
}

async function fetchGmailProfile(token) {
    const response = await fetch("https://gmail.googleapis.com/gmail/v1/users/me/profile", {
        headers: {
            Authorization: `Bearer ${token}`
        }
    });

    if (!response.ok) {
        throw new Error(`Gmail profile request failed: ${response.status}`);
    }

    const data = await response.json();
    return {
        emailAddress: data.emailAddress,
        messagesTotal: data.messagesTotal,
        threadsTotal: data.threadsTotal
    };
}

function base64UrlToUint8Array(base64Url) {
    const base64 = (base64Url || "").replace(/-/g, "+").replace(/_/g, "/");
    const padding = "=".repeat((4 - (base64.length % 4)) % 4);
    const binary = atob(base64 + padding);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i += 1) {
        bytes[i] = binary.charCodeAt(i);
    }
    return bytes;
}

async function sha256Hex(bytes) {
    const digest = await crypto.subtle.digest("SHA-256", bytes);
    const view = new Uint8Array(digest);
    return Array.from(view).map((b) => b.toString(16).padStart(2, "0")).join("");
}

async function gmailApiGet(token, path) {
    const response = await fetch(`https://gmail.googleapis.com/gmail/v1/${path}`, {
        headers: { Authorization: `Bearer ${token}` }
    });
    if (!response.ok) {
        throw new Error(`Gmail API failed ${response.status} for ${path}`);
    }
    return response.json();
}

async function gmailApiPost(token, path, body) {
    const response = await fetch(`https://gmail.googleapis.com/gmail/v1/${path}`, {
        method: "POST",
        headers: {
            Authorization: `Bearer ${token}`,
            "Content-Type": "application/json"
        },
        body: JSON.stringify(body || {})
    });
    if (!response.ok) {
        throw new Error(`Gmail API failed ${response.status} for ${path}`);
    }
    return response.json();
}

function collectAttachmentParts(part, acc) {
    if (!part) {
        return;
    }
    const hasAttachment = Boolean(part.filename) && Boolean(part.body?.attachmentId);
    if (hasAttachment) {
        acc.push({
            filename: part.filename,
            attachmentId: part.body.attachmentId,
            contentType: part.mimeType || ""
        });
    }
    if (Array.isArray(part.parts)) {
        for (const child of part.parts) {
            collectAttachmentParts(child, acc);
        }
    }
}

async function fetchAttachmentHashesForMessage(token, messageId) {
    const message = await gmailApiGet(token, `users/me/messages/${messageId}?format=full`);
    const collected = [];
    collectAttachmentParts(message.payload, collected);
    console.log("[PhishGuard][BG] Gmail attachment parts found:", collected.length, "for message:", messageId);

    const result = [];
    for (const item of collected) {
        try {
            const attachment = await gmailApiGet(
                token,
                `users/me/messages/${messageId}/attachments/${item.attachmentId}`
            );
            const bytes = base64UrlToUint8Array(attachment.data || "");
            const sha256 = await sha256Hex(bytes);
            result.push({
                filename: item.filename,
                content_type: item.contentType,
                sha256
            });
            console.log("[PhishGuard][BG] Hash computed:", item.filename);
        } catch (error) {
            result.push({
                filename: item.filename,
                content_type: item.contentType,
                hash_error: String(error?.message || error)
            });
            console.warn("[PhishGuard][BG] Hash failed:", item.filename, String(error?.message || error));
        }
    }
    return result;
}

ext.runtime.onMessage.addListener((request, sender, sendResponse) => {
    if (request?.type === "GMAIL_AUTH_TEST") {
        console.log("[PhishGuard][BG] GMAIL_AUTH_TEST received");

        (async () => {
            try {
                const token = await getAuthTokenInteractive();
                const profile = await fetchGmailProfile(token);
                console.log("[PhishGuard][BG] Gmail OAuth success:", profile?.emailAddress || "unknown");
                sendResponse({ ok: true, profile });
            } catch (error) {
                console.warn("[PhishGuard][BG] Gmail OAuth failed:", String(error?.message || error));
                sendResponse({
                    ok: false,
                    error: String(error?.message || error)
                });
            }
        })();

        return true;
    }

    if (request?.type === "GMAIL_GET_ATTACHMENT_HASHES") {
        (async () => {
            try {
                const messageId = String(request?.messageId || "").trim();
                if (!messageId) {
                    throw new Error("Missing Gmail messageId");
                }
                const token = await getAuthTokenInteractive();
                const attachments = await fetchAttachmentHashesForMessage(token, messageId);
                const hashedCount = attachments.filter(item => item.sha256).length;
                console.log("[PhishGuard][BG] Attachment hash result:", {
                    messageId,
                    total: attachments.length,
                    hashed: hashedCount
                });
                sendResponse({ ok: true, attachments });
            } catch (error) {
                console.warn("[PhishGuard][BG] GMAIL_GET_ATTACHMENT_HASHES failed:", String(error?.message || error));
                sendResponse({
                    ok: false,
                    error: String(error?.message || error),
                    attachments: []
                });
            }
        })();

        return true;
    }

    if (request?.type === "GMAIL_MOVE_TO_SPAM") {
        (async () => {
            try {
                const messageId = String(request?.messageId || "").trim();
                if (!messageId) {
                    throw new Error("Missing Gmail messageId");
                }
                const token = await getAuthTokenInteractive();
                await gmailApiPost(token, `users/me/messages/${messageId}/modify`, {
                    addLabelIds: ["SPAM"],
                    removeLabelIds: ["INBOX"]
                });
                console.log("[PhishGuard][BG] Message moved to spam:", messageId);
                sendResponse({ ok: true });
            } catch (error) {
                console.warn("[PhishGuard][BG] GMAIL_MOVE_TO_SPAM failed:", String(error?.message || error));
                sendResponse({
                    ok: false,
                    error: String(error?.message || error)
                });
            }
        })();

        return true;
    }

    return false;
});
