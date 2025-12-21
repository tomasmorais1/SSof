user = request.GET["user"]
safe = escape(user)
unsafe = safe + request.GET["suffix"]
html = mark_safe(unsafe)


