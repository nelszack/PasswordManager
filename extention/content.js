function createDropdownButton(input, accounts) {
    if (input.dataset.hasCredentialDropdown) return;
    input.dataset.hasCredentialDropdown = "true";

    // Create button
    const button = document.createElement("button");
    button.type = "button";
    button.innerText = "🔑";
    Object.assign(button.style, {
        position: "absolute",
        border: "none",
        background: "transparent",
        cursor: "pointer",
        fontSize: "16px",
        zIndex: "2147483647",
        padding: "0",
        margin: "0"
    });

    document.body.appendChild(button);

    // Position button relative to input
    function positionButton() {
        const rect = input.getBoundingClientRect();
        button.style.left = rect.right - 22 + "px";
        button.style.top = rect.top + rect.height / 2-15 + "px";
    }

    positionButton();
    window.addEventListener("scroll", positionButton);
    window.addEventListener("resize", positionButton);

    // Create dropdown
    const menu = document.createElement("div");
    Object.assign(menu.style, {
        position: "absolute",
        background: "#fff",
        border: "1px solid #ccc",
        display: "none",
        zIndex: "2147483647",
        minWidth: "180px",
        boxShadow: "0 4px 12px rgba(0,0,0,0.25)"
    });

    document.body.appendChild(menu);

    function positionMenu() {
        const rect = button.getBoundingClientRect();
        menu.style.left = rect.left + "px";
        menu.style.top = rect.bottom + "px";
    }

    accounts.forEach(acc => {
        const item = document.createElement("div");
        item.innerText = acc.username;
        Object.assign(item.style, {
            padding: "8px 12px",
            cursor: "pointer"
        });

        item.addEventListener("mouseenter", () => {
            item.style.background = "#eee";
        });

        item.addEventListener("mouseleave", () => {
            item.style.background = "#fff";
        });

        item.addEventListener("click", (e) => {
            e.preventDefault();

            if (input.type !== "password") {
                input.value = acc.username;
                input.dispatchEvent(new Event("input", { bubbles: true }));
            }

            const passwordField = document.querySelector("input[type='password']");
            if (passwordField) {
                passwordField.value = acc.password;
                passwordField.dispatchEvent(new Event("input", { bubbles: true }));
            }

            menu.style.display = "none";
        });

        menu.appendChild(item);
    });

    button.addEventListener("click", (e) => {
        e.preventDefault();
        e.stopPropagation();

        if (menu.style.display === "block") {
            menu.style.display = "none";
        } else {
            positionMenu();
            menu.style.display = "block";
        }
    });

    document.addEventListener("click", (e) => {
        if (!menu.contains(e.target) && e.target !== button) {
            menu.style.display = "none";
        }
    });
}

// ===============================
// Attach to all valid inputs
// ===============================
function attachToInputs(accounts) {
    const inputs = document.querySelectorAll(
        "input[type='text'], input[type='email'], input[type='password']"
    );

    inputs.forEach(input => {
        // Ignore extension UI elements
        if (input.classList.contains("my-extension-ui")) return;
        createDropdownButton(input, accounts);
    });
}

// ===============================
// Observe DOM safely (no loop)
// ===============================
function observeInputs(accounts) {
    const observer = new MutationObserver((mutations) => {
        let foundNewInput = false;

        for (const mutation of mutations) {
            for (const node of mutation.addedNodes) {
                if (
                    node.nodeType === 1 &&
                    node.querySelector &&
                    node.querySelector("input")
                ) {
                    foundNewInput = true;
                }
            }
        }

        if (foundNewInput) {
            attachToInputs(accounts);
        }
    });

    observer.observe(document.body, {
        childList: true,
        subtree: true
    });

    // Initial run
    attachToInputs(accounts);
}

// ===============================
// Request credentials from background
// ===============================
chrome.runtime.sendMessage(
    { action: "getCredentials", domain: window.location.href },
    (response) => {
        if (
            response &&
            response.success
        ) {
            try {
                let data = JSON.parse(response.data)
                observeInputs(data)
                
            } catch (error) {
                
            }
        }
    }
);