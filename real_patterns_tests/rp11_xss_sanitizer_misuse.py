comment = get("comment")
escape(comment)          # sanitizer called, but return value ignored
mark_safe(comment)       # still unsanitized


