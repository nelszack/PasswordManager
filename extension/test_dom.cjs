// A minimal DOM for content-script unit tests: enough element structure, styles,
// events and shadow roots for controls and the generator, without a browser.
class FakeStyle {
    constructor(owner) {
        this.owner = owner;
        this.values = new Map();
        this.priorities = new Map();
    }
    getPropertyValue(name) {
        return this.values.get(name) ?? "";
    }
    getPropertyPriority(name) {
        return this.priorities.get(name) ?? "";
    }
    setProperty(name, value, priority = "") {
        this.values.set(name, value);
        this.priorities.set(name, priority);
        this.owner.document.styleWrites++;
    }
    get display() {
        return this.getPropertyValue("display");
    }
    get left() {
        return this.getPropertyValue("left");
    }
    get top() {
        return this.getPropertyValue("top");
    }
}

class FakeNode {
    constructor(document) {
        this.document = document;
        this.parentNode = null;
        this.childNodes = [];
        this.listeners = new Map();
    }
    get children() {
        return this.childNodes.filter(node => node.nodeType === 1);
    }
    get parentElement() {
        return this.parentNode?.nodeType === 1 ? this.parentNode : null;
    }
    get isConnected() {
        for (let node = this; node; node = node.parentNode || node.host) if (node === this.document) return true;
        return false;
    }
    appendChild(child) {
        child.remove?.();
        child.parentNode = this;
        this.childNodes.push(child);
        return child;
    }
    append(...children) {
        for (const child of children) this.appendChild(child);
    }
    replaceChildren(...children) {
        for (const child of this.childNodes) child.parentNode = null;
        this.childNodes = [];
        this.append(...children);
    }
    contains(node) {
        for (; node; node = node.parentNode) if (node === this) return true;
        return false;
    }
    getRootNode() {
        let node = this;
        while (node.parentNode) node = node.parentNode;
        return node;
    }
    addEventListener(type, listener, options = {}) {
        if (!this.listeners.has(type)) this.listeners.set(type, []);
        this.listeners.get(type).push(listener);
        options?.signal?.addEventListener?.("abort", () => this.removeEventListener(type, listener));
    }
    removeEventListener(type, listener) {
        this.listeners.set(
            type,
            (this.listeners.get(type) || []).filter(candidate => candidate !== listener)
        );
    }
    dispatch(type, event = {}) {
        const dispatched = { type, target: this, isTrusted: true, preventDefault() {}, stopPropagation() {}, ...event };
        for (const listener of [...(this.listeners.get(type) || [])]) listener(dispatched);
        return dispatched;
    }
    descendants() {
        return this.children.flatMap(child => [child, ...child.descendants()]);
    }
    querySelectorAll(selector) {
        return this.descendants().filter(element => element.matches(selector));
    }
    get textContent() {
        return this.childNodes.map(node => node.textContent).join("");
    }
    set textContent(value) {
        this.replaceChildren();
        if (value) this.appendChild(new FakeText(this.document, String(value)));
    }
}

class FakeText extends FakeNode {
    constructor(document, data) {
        super(document);
        this.nodeType = 3;
        this.data = data;
    }
    get textContent() {
        return this.data;
    }
    remove() {
        if (!this.parentNode) return;
        this.parentNode.childNodes = this.parentNode.childNodes.filter(node => node !== this);
        this.parentNode = null;
    }
}

class FakeElement extends FakeNode {
    constructor(document, localName) {
        super(document);
        this.nodeType = 1;
        this.localName = localName;
        this.tagName = localName.toUpperCase();
        this.attributes = new Map();
        this.style = new FakeStyle(this);
        this.dataset = {};
        this.shadowRoot = null;
        this.rect = { left: 0, top: 0, right: 0, bottom: 0, width: 0, height: 0 };
    }
    get id() {
        return this.getAttribute("id") || "";
    }
    set id(value) {
        this.setAttribute("id", value);
    }
    get title() {
        return this.getAttribute("title") || "";
    }
    set title(value) {
        this.setAttribute("title", value);
    }
    setAttribute(name, value) {
        this.attributes.set(name, String(value));
    }
    getAttribute(name) {
        return this.attributes.has(name) ? this.attributes.get(name) : null;
    }
    hasAttribute(name) {
        return this.attributes.has(name);
    }
    removeAttribute(name) {
        this.attributes.delete(name);
    }
    // Supports "*", "tag", "[attr='value']" and "tag[attr='value']" lists.
    matches(selector) {
        return selector.split(",").some(part => {
            const match = part.trim().match(/^(\*|[a-z-]*)(?:\[([a-z-]+)='([^']*)'\])?$/);
            if (!match) throw new Error(`Unsupported test selector: ${part}`);
            const [, tag, attribute, value] = match;
            if (tag === "*") return true;
            if (tag && tag !== this.localName) return false;
            if (!attribute) return Boolean(tag);
            const actual = attribute === "type" && "type" in this ? this.type : this.getAttribute(attribute);
            return actual === value;
        });
    }
    closest(selector) {
        for (let node = this; node && node.nodeType === 1; node = node.parentNode)
            if (node.matches(selector)) return node;
        return null;
    }
    remove() {
        if (!this.parentNode) return;
        this.parentNode.childNodes = this.parentNode.childNodes.filter(node => node !== this);
        this.parentNode = null;
    }
    insertAdjacentElement(position, element) {
        if (position !== "afterend" || !this.parentNode) return null;
        element.remove();
        const siblings = this.parentNode.childNodes;
        siblings.splice(siblings.indexOf(this) + 1, 0, element);
        element.parentNode = this.parentNode;
        return element;
    }
    get nextElementSibling() {
        const siblings = this.parentNode?.children || [];
        return siblings[siblings.indexOf(this) + 1] || null;
    }
    attachShadow({ mode }) {
        if (this.shadowRoot || this.attachedShadow) throw new Error("Shadow root already attached");
        const root = new FakeNode(this.document);
        root.host = this;
        root.mode = mode;
        this.attachedShadow = root;
        // Closed roots are not reachable through the host, as in browsers.
        if (mode === "open") this.shadowRoot = root;
        return root;
    }
    getBoundingClientRect() {
        return this.rect;
    }
    focus() {
        this.document.activeElement = this;
    }
    click(event = {}) {
        return this.dispatch("click", event);
    }
}

class FakeInput extends FakeElement {
    constructor(document, type = "text") {
        super(document, "input");
        this.type = type;
        this.value = "";
        this.disabled = false;
        this.readOnly = false;
        this.autocomplete = "";
        this.name = "";
        this.className = "";
    }
}

Object.defineProperty(FakeInput.prototype, "form", {
    get() {
        return this.parentNode ? this.closest("form") : null;
    },
});

class FakeButton extends FakeElement {
    constructor(document) {
        super(document, "button");
    }
    get type() {
        const type = String(this.getAttribute("type") || "").toLowerCase();
        return ["button", "reset"].includes(type) ? type : "submit";
    }
    set type(value) {
        this.setAttribute("type", value);
    }
    get form() {
        return this.parentNode ? this.closest("form") : null;
    }
}

class FakeForm extends FakeElement {
    constructor(document) {
        super(document, "form");
    }
    get elements() {
        return this.descendants().filter(element => element instanceof FakeInput);
    }
}

function createDocument() {
    const document = new FakeNode(null);
    document.document = document;
    document.nodeType = 9;
    document.styleWrites = 0;
    document.activeElement = null;
    document.createElement = name =>
        name === "input"
            ? new FakeInput(document)
            : name === "form"
              ? new FakeForm(document)
              : name === "button"
                ? new FakeButton(document)
                : new FakeElement(document, name);
    document.createElementNS = (_namespace, name) => new FakeElement(document, name);
    document.body = document.appendChild(new FakeElement(document, "body"));
    document.hits = [];
    document.elementsFromPoint = () => document.hits;
    return document;
}

// Install browser globals for a test and restore them afterwards.
function installDom(t, extra = {}) {
    const document = createDocument();
    const frames = [];
    const windowListeners = new Map();
    const window = {
        innerWidth: 1280,
        innerHeight: 800,
        addEventListener(type, listener, options) {
            if (!windowListeners.has(type)) windowListeners.set(type, []);
            windowListeners.get(type).push(listener);
            options?.signal?.addEventListener?.("abort", () =>
                windowListeners.set(
                    type,
                    windowListeners.get(type).filter(candidate => candidate !== listener)
                )
            );
        },
        removeEventListener() {},
    };
    const globals = {
        document,
        window,
        HTMLInputElement: FakeInput,
        HTMLFormElement: FakeForm,
        HTMLButtonElement: FakeButton,
        HTMLSelectElement: class {},
        HTMLTextAreaElement: class {},
        Element: FakeElement,
        requestAnimationFrame: callback => frames.push(callback),
        getComputedStyle: element => ({
            display: element.hiddenForTest ? "none" : "block",
            visibility: "visible",
            opacity: "1",
        }),
        ResizeObserver: class {
            observe() {}
            unobserve() {}
            disconnect() {}
        },
        ...extra,
    };
    const previous = new Map(Object.keys(globals).map(key => [key, Object.getOwnPropertyDescriptor(global, key)]));
    for (const [key, value] of Object.entries(globals))
        Object.defineProperty(global, key, { value, configurable: true, writable: true });
    const cleanups = [];
    t.after(() => {
        // Dispose content controllers while their browser globals still exist.
        for (const cleanup of cleanups.reverse()) cleanup();
        for (const [key, descriptor] of previous) {
            if (descriptor) Object.defineProperty(global, key, descriptor);
            else delete global[key];
        }
    });
    return {
        document,
        window,
        frames,
        cleanup: callback => cleanups.push(callback),
        flushFrames() {
            while (frames.length) frames.shift()();
        },
        fireWindow(type, event = {}) {
            for (const listener of [...(windowListeners.get(type) || [])]) listener({ type, ...event });
        },
        input(type = "text", rect = { left: 20, top: 10, right: 220, bottom: 40, width: 200, height: 30 }) {
            const input = document.createElement("input");
            input.type = type;
            input.rect = rect;
            return input;
        },
    };
}

module.exports = { installDom, createDocument, FakeButton, FakeElement, FakeForm, FakeInput };
