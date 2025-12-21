comment = request.GET["comment"]
tmp = escape(comment)
safe = clean(tmp)
html = mark_safe(safe)


