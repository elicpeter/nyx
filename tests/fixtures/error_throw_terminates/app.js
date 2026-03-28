function processRequest(req, res) {
    const data = getWorkspaceData(req.params.id);
    if (!data) {
        throw new Error("Not found");
    }
    db.query(`SELECT * FROM projects WHERE workspace_id = ${data.id}`);
}
