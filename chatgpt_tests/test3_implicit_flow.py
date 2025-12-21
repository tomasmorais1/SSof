flag = request.GET["is_admin"]
if flag:
    query = "DELETE FROM users"
else:
    query = "SELECT * FROM users"
db.execute(query)


