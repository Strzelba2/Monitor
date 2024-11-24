import logging

class PasswordMaskFilter(logging.Filter):
    def filter(self, record):
        if isinstance(record.msg, str):
            password_pos = record.msg.find("password") 
        else:
            password_pos = -1

        if password_pos == -1:
            return True
        
        after_password = record.msg[password_pos + len("password"):]
        after_password = after_password.lstrip(": ")
        words = after_password.split()
        for word in words:
            if len(word)>3:
                masked_word = '*' * len(word)
                record.msg = record.msg.replace(word,masked_word)
                break
        return True