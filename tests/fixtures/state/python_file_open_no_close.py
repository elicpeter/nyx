def file_leak():
    f = open("data.txt", "r")
    f.read()
    # Missing f.close() — resource leak
