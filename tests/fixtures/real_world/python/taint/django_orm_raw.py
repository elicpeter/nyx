from django.http import HttpResponse

def user_search(request):
    query = request.GET.get("q")
    results = User.objects.raw("SELECT * FROM users WHERE name = '%s'" % query)
    return HttpResponse(str(results))
