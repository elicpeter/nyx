from flask import Flask, request

app = Flask(__name__)


def admin_required(fn):
    return fn


class AdminService:
    def update_user_role(self, user_id, role):
        return None


admin_service = AdminService()


@app.post("/admin/users/<int:user_id>/role")
@admin_required
def update_user_role(user_id):
    admin_service.update_user_role(user_id, request.json["role"])
    return {"ok": True}
