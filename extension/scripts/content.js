const ext = globalThis.browser ?? globalThis.chrome;

ext.runtime.onMessage.addListener((request, sender, sendResponse) => {
    if (request.type !== "EXTRACT_EMAIL") {
        return false;
    }

    const emailContainer = document.querySelector(".ii.gt");

    if (!emailContainer) {
        sendResponse({ body: "", links: [] });
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

    sendResponse({
        body: bodyText,
        links
    });

    return true;
});
