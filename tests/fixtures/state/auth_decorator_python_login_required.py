import os


@login_required
def handle_request(request):
    # Decorator seeds AuthLevel::Authed — state-unauthed-access suppressed.
    os.system("ls /tmp")
