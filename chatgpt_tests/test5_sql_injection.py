user = request.GET["user"]
safe_user = escape_string(user)
query = "SELECT * FROM users WHERE name='%s'" % safe_user
db.execute(query)


