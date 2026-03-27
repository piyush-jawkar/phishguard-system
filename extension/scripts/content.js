const ext = globalThis.browser ?? globalThis.chrome;

function extractGmailMessageContext(emailContainer, messageRoot) {
    const messageNodeCandidates = [
        messageRoot,
        emailContainer?.closest("[data-legacy-message-id]"),
        document.querySelector("[data-legacy-message-id]"),
        document.querySelector("[data-message-id]")
    ].filter(Boolean);

    for (const node of messageNodeCandidates) {
        const legacyMessageId = (node.getAttribute?.("data-legacy-message-id") || "").trim();
        const messageIdAttr = (node.getAttribute?.("data-message-id") || "").trim();
        const legacyThreadId = (node.getAttribute?.("data-legacy-thread-id") || "").trim();

        const normalizedMessageId = legacyMessageId || messageIdAttr.replace(/^msg-[af]:/i, "");
        if (normalizedMessageId) {
            return {
                messageId: normalizedMessageId,
                threadId: legacyThreadId || null
            };
        }
    }

    return { messageId: null, threadId: null };
}

ext.runtime.onMessage.addListener((request, sender, sendResponse) => {
    if (request.type !== "EXTRACT_EMAIL") {
        return false;
    }

    const emailContainer = document.querySelector(".ii.gt");
    const messageRoot =
        emailContainer?.closest(".adn.ads") ||
        document.querySelector(".adn.ads") ||
        document;

    if (!emailContainer) {
        sendResponse({ body: "", links: [], attachments: [] });
        return true;
    }

    const bodyText = emailContainer.innerText;
    const linkElements = emailContainer.querySelectorAll("a");

    const links = Array.from(linkElements)
        .map(a => a.href)
        .filter(link =>
            link &&
            !link.includes("mail.google.com") &&
            !link.includes("accounts.google.com") &&
            !link.includes("support.google.com")
        );

    const attachmentSelectors = [
        ".aQH",
        ".aZo",
        "span.aQA",
        "span.aV3",
        "a[href*='view=att']",
        "a[data-tooltip*='Download']",
        "div[download_url]"
    ];
    const attachmentNodes = messageRoot.querySelectorAll(attachmentSelectors.join(","));
    const attachments = Array.from(attachmentNodes)
        .map(node => {
            const text = (node.textContent || "").trim();
            const title = (node.getAttribute("title") || "").trim();
            const aria = (node.getAttribute("aria-label") || "").trim();
            const downloadUrl = (node.getAttribute("download_url") || "").trim();
            const filenameFromDownload = downloadUrl.includes(":")
                ? downloadUrl.split(":").pop().trim()
                : "";

            const candidates = [text, title, aria, filenameFromDownload];
            const filename = candidates.find(name => /\.[a-z0-9]{2,8}$/i.test(name || ""));

            if (!filename) {
                return null;
            }

            return { filename };
        })
        .filter(Boolean);
    const dedupedAttachments = Array.from(
        new Map(attachments.map(item => [item.filename.toLowerCase(), item])).values()
    );
    const messageContext = extractGmailMessageContext(emailContainer, messageRoot);

    sendResponse({
        body: bodyText,
        links,
        attachments: dedupedAttachments,
        message_id: messageContext.messageId,
        thread_id: messageContext.threadId
    });

    return true;
});
