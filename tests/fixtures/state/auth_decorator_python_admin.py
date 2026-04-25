import os


# `admin_required` classifies as `Admin`, which subsumes `Authed`.
# The privileged sink should NOT flag state-unauthed-access.
@admin_required
def handle_admin(request):
    os.system("service nginx restart")
