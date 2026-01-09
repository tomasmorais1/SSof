comment = get("comment")
safe_comment = escape(comment)
out1 = mark_safe(comment)
out2 = mark_safe(safe_comment)


