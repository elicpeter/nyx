from flask import Flask

app = Flask(__name__)


def login_required(fn):
    return fn


class AuditService:
    def publish(self):
        return None


audit_service = AuditService()


@app.post("/admin/projects/archive")
@login_required
def archive_project():
    audit_service.publish()
    return {"ok": True}
