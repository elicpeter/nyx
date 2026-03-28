const { exec } = require("child_process");

function execAsync(command) {
    return new Promise((resolve, reject) => {
        exec(command, (error, stdout, stderr) => {
            if (error) {
                reject(error);
            } else {
                resolve(stdout);
            }
        });
    });
}

async function exportWorkspace(req, res) {
    const src = req.body.src;
    const dst = req.body.dst;
    // VULN: user-controlled input flows into execAsync wrapper
    await execAsync(`cp ${src} ${dst}`);
    res.json({ status: "ok" });
}
