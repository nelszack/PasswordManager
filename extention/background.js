chrome.runtime.onInstalled.addListener(() => {
    console.log("Password Manager Extension Installed");
});

chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    if (request.action === "getCredentials") {
        fetch("http://localhost:7878",{
            method: "POST",
            headers: {
                "Content-Type": "text/plain",
                "Connection": "close"
            },
            body: JSON.stringify({
                command: "get",
                extra_info: [request.domain]
            })
        })
            .then(res => res.text())
            .then(data => sendResponse({ success: true, data }))
            .catch(err => sendResponse({ success: false, error: err.toString() }));
        return true; // keeps the message channel open for async response
    }
});