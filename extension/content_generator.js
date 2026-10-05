function secureRandomIndex(limit) {
    const ceiling = Math.floor(0x100000000 / limit) * limit;
    const value = new Uint32Array(1);
    do {
        crypto.getRandomValues(value);
    } while (value[0] >= ceiling);
    return value[0] % limit;
}

function generatePagePassword(length = 20) {
    const groups = [
        "ABCDEFGHJKLMNPQRSTUVWXYZ",
        "abcdefghijkmnopqrstuvwxyz",
        "23456789",
        "!@#$%^&*-_=+"
    ];
    const all = groups.join("");
    const characters = groups.map(group => group[secureRandomIndex(group.length)]);
    while (characters.length < length) {
        characters.push(all[secureRandomIndex(all.length)]);
    }
    for (let index = characters.length - 1; index > 0; index--) {
        const swap = secureRandomIndex(index + 1);
        [characters[index], characters[swap]] = [characters[swap], characters[index]];
    }
    return characters.join("");
}

const generatorControls = new WeakMap();

function removeGeneratorButton(input) {
    generatorControls.get(input)?.remove();
}

function createGeneratorButton(input) {
    const existing = generatorControls.get(input);
    if (existing) {
        existing.position();
        return;
    }

    const button = document.createElement("button");
    button.type = "button";
    button.className = "my-extension-ui";
    button.innerText = "✨";
    button.title = "Generate a strong password";
    button.setAttribute("aria-label", "Generate a strong password");
    Object.assign(button.style, {
        position: "fixed",
        border: "none",
        background: "transparent",
        cursor: "pointer",
        fontSize: "15px",
        zIndex: "2147483647",
        padding: "0",
        margin: "0",
        display: "none"
    });
    document.body.appendChild(button);

    function positionButton() {
        if (!isElementVisible(input)) {
            button.style.display = "none";
            return;
        }
        const rect = input.getBoundingClientRect();
        if (rect.width === 0 || rect.height === 0) {
            button.style.display = "none";
            return;
        }
        button.style.display = "";
        button.style.left = rect.right - 24 + "px";
        button.style.top = rect.top + rect.height / 2 - 14 + "px";
    }

    button.addEventListener("click", event => {
        event.preventDefault();
        event.stopPropagation();
        const password = generatePagePassword();
        const fields = scopeInputs(credentialScope(input)).filter(isNewPasswordInput);
        const targets = fields.length > 0 ? fields : [input];
        targets.forEach(field => fillInput(field, password));
        lastCredentialInput = input;
        input.focus();
        button.title = "Strong password generated and filled";
    });

    positionButton();
    const control = { position: positionButton, remove: null };
    control.remove = registerPositionedControl(input, button, positionButton, () => {
        if (generatorControls.get(input) === control) generatorControls.delete(input);
    });
    generatorControls.set(input, control);
}
