from django.http import HttpResponse
from django.db import connection

def search(request):
    ch = request.GET.get("c")
    code = ord(ch)
    cursor = connection.cursor()
    cursor.execute("SELECT * FROM items WHERE code = " + code)
    return HttpResponse("ok")
