import express from 'express';
const app = express();

app.get('/action', (req: express.Request, res: express.Response) => {
    const action: string = req.query.action as string;
    if (action === "safe") {
        if (action === "dangerous") {
            // Infeasible: action === "safe" AND action === "dangerous"
            eval(action);
        }
    }
    eval(action);
});
