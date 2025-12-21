mode = get("mode")
if mode == "1":
    q = "SELECT * FROM users"
else:
    q = "SELECT * FROM admins"
execute(q)


