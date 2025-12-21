x = request.GET["x"]
if False:
    y = x
else:
    y = "safe"
html = mark_safe(y)


