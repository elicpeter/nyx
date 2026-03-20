from django.http import HttpResponse
from django.db import connection

def search(request):
    q = request.GET.get("q")
    cursor = connection.cursor()
    cursor.execute("SELECT * FROM items WHERE name = '" + q + "'")
    results = cursor.fetchall()
    return HttpResponse(str(results))
