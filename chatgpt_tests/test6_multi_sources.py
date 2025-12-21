name = request.GET["name"]
email = request.GET["email"]
safe_name = escape(name)
query = "INSERT INTO users VALUES ('%s','%s')" % (safe_name, email)
db.execute(query)


