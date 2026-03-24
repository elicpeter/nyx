import subprocess

@login_required
def handle_request(request):
    # Decorator should suppress, but decorator detection not implemented yet
    subprocess.call(request.POST['cmd'], shell=True)
