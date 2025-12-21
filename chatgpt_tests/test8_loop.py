data = request.GET["data"]
result = ""
while data:
    result = result + data
    break
html = mark_safe(result)


