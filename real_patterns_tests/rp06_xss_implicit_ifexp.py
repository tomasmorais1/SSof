user_flag = get("show_admin")
content = "<p>admin</p>" if user_flag == "1" else "<p>guest</p>"
mark_safe(content)


