chrome.runtime.onInstalled.addListener(() => {
    console.log("Password Manager Extension Installed");
});

function loadToken() {
    return new Promise((resolve) => {
        chrome.storage.local.get("pmServerToken", (result) => {
            resolve(result.pmServerToken || "");
        });
    });
}

async function post(command, extra_info) {
    const token = await loadToken();
    if (!token) {
        return { error: "missing-token" };
    }
    const res = await fetch("http://localhost:7878", {
        method: "POST",
        headers: {
            "Content-Type": "application/json",
            "Authorization": "Bearer " + token,
            "Connection": "close"
        },
        body: JSON.stringify({ command, extra_info })
    });
    return { res };
}

chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    if (request.action === "getCredentials") {
        post("get", [request.domain])
            .then(({ res, error }) => {
                if (error) return sendResponse({ success: false, error });
                return res.json().then(data => sendResponse({ success: true, data }));
            })
            .catch(err => sendResponse({ success: false, error: err.toString() }));
        return true; // keeps the message channel open for async response
    }
    if (request.action === "saveCredentials") {
        post("add", [request.domain, request.username, request.password, request.name])
            .then(({ res, error }) => {
                if (error) return sendResponse({ success: false, error });
                return res.text().then(data => sendResponse({ success: true, data }));
            })
            .catch(err => sendResponse({ success: false, error: err.toString() }));
        return true;
    }

    if (request.action === "updateCredentials") {
        post("update", [request.domain, request.username, request.password, request.name, request.id])
            .then(({ res, error }) => {
                if (error) return sendResponse({ success: false, error });
                return res.text().then(data => sendResponse({ success: true, data }));
            })
            .catch(err => sendResponse({ success: false, error: err.toString() }));
        return true;
    }
});
