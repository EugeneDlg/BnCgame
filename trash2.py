from itertools import permutations as permut
import secrets
import re
import base64
# print(base64.b64encode("bncdflt1!".encode("ascii")).decode("ascii"))
# print(base64.b64encode("tP$sa7Ml".encode("ascii")).decode("ascii"))
# from functools import reduce
print(base64.b64encode("CsK01EWBy1UkqQmd1xq2".encode("ascii")).decode("ascii"))

a = [6,7,8,9]
b = [1, "a", "a", "a"]
lst0 = list(permut(b,4))
set0 = set(lst0)
# cows = 1
# bulls = 0
# perm0 = list(permut("1234", cows))
# t = [print(i) for i in perm0]
# perm_lst = list()
# for i0 in perm0:
#     list_i = list(i0)
#     list_i.extend("V" * (4-cows))
#     perm1 = permut(list_i, 4)
#     perm_lst.append(list(perm1))
# perm_set = set(perm_lst)
## [print(i) for i in perm_lst]

import smtplib
import ssl
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from passlib.context import CryptContext
SSL_PORT = 465
SMTP_ADDRESS = "smtp.mail.ru"
BNC_EMAIL = "Bulls.And.Cows@mail.ru"
text = """\
Subject: Restoring your password

Hello dear customer!
Your pincode for password recovering: PINCODE
Thank you for contacting us. Have a nice day!
"""
html = """\
<html>
  <body>
    <p><h3>Hello dear customer!</h3><br>
       We have received a request from you to recover your password.<br>
       Your pincode for password recovery: <h4>PINCODE<h/4><br><br>
       Thank you for contacting us. Have a nice day!<br>
        -- Best regards, BnC team. 
    </p>
  </body>
</html>
"""


def send_pincode():
    # return
    password = base64.b64decode("Q3NLMDFFV0J5MVVrcVFtZDF4cTI=".encode("ascii")).decode("ascii")
    email_msg = MIMEMultipart("alternative")
    sender_email = BNC_EMAIL
    receiver_email = "stayerx@gmail.com"
    email_msg["Subject"] = "Recover your password"
    email_msg["From"] = sender_email
    email_msg["To"] = receiver_email
    text_for_restoring_password = text
    html_for_restoring_password = html
    p1 = MIMEText(text_for_restoring_password, "plain")
    p2 = MIMEText(html_for_restoring_password, "html")
    email_msg.attach(p1)
    email_msg.attach(p2)
    context = ssl.create_default_context()
    try:

        with smtplib.SMTP_SSL(SMTP_ADDRESS, SSL_PORT, context=context) as srv:
            srv.login(BNC_EMAIL, password)
            srv.sendmail(sender_email, receiver_email, email_msg.as_string())
    except Exception:
        raise

# send_pincode()





