comment = request.GET["comment"]
safe = escape(comment)
html = mark_safe(safe)


