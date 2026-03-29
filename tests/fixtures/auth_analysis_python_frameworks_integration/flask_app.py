from flask import Flask, request

app = Flask(__name__)


def login_required(fn):
    return fn


class AdminService:
    def update_role(self, user_id, role):
        return None


class ProjectStore:
    def update_state(self, project_id, state):
        return None


admin_service = AdminService()
project_store = ProjectStore()


@app.post("/admin/users/<int:user_id>/role")
@login_required
def update_role(user_id):
    admin_service.update_role(user_id, request.json["role"])
    return {"ok": True}


@app.post("/projects/<int:project_id>/state")
def update_state(project_id):
    project_store.update_state(project_id, request.json["state"])
    return {"ok": True}
