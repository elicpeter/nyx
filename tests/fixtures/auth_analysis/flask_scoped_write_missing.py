from flask import Flask, request

app = Flask(__name__)


class ProjectStore:
    def update_state(self, project_id, payload):
        return None


project_store = ProjectStore()


@app.post("/projects/<int:project_id>/state")
def update_project_state(project_id):
    project_store.update_state(project_id, request.json["state"])
    return {"ok": True}
