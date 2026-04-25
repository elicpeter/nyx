import os


@permission_required("view_user")
def handle_user(request):
    os.system("cat /etc/passwd")
