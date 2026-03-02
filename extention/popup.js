const SERVER_URL = "http://127.0.0.1:7878";

async function sendCommand(command, extra_info = []) {
    try {
        const response = await fetch(SERVER_URL, {
            method: "POST",
            headers: {
                "Content-Type": "text/plain",
                "Connection": "close"
            },
            body: JSON.stringify({
                command: command,
                extra_info: extra_info
            })
        });

        const data = await response.text();
        return data;
    } catch (error) {
        console.log(error)
        return "Server not reachable"
    }
}

document.getElementById("statusBtn").addEventListener("click", async () => {
    const result = await sendCommand("status");
    document.getElementById("output").innerText =
        // JSON.stringify(result, null, 2);
        result
});

document.getElementById("getBtn").addEventListener("click", async () => {
    const site = prompt("Enter site name:");
    const result = await sendCommand("get", [site]);
    document.getElementById("output").innerText =
        // JSON.stringify(result, null, 2);
        result
});

document.getElementById("lockBtn").addEventListener("click", async () => {
    const result = await sendCommand("lock", ["true"]);
    document.getElementById("output").innerText =
        // JSON.stringify(result, null, 2);
        result
});