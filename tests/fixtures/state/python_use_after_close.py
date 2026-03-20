def use_after_close():
    f = open("data.txt", "r")
    f.close()
    f.read()
