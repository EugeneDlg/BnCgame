from itertools import permutations as permut
import secrets

# "UWV0dTEyMyE="
# import re
# import base64
#
#
# def base64_decode_(encoded_string):
#     return base64.b64decode(encoded_string.encode("ascii")).decode("ascii")
#
# DB_CONN_STRING0 = "postgresql+psycopg2://postgres:tP$sa7Ml@127.0.0.1:5432/bnc"
# DB_CONN_STRING = "postgresql+psycopg2://postgres:dFAkc2E3TWw=@127.0.0.1:5432/bnc"
# m = re.search(r":([^/].+)@", DB_CONN_STRING)
# gg = DB_CONN_STRING.replace(m.group(1), base64_decode_(m.group(1)))
# print(DB_CONN_STRING)
# print(gg)
#
# print(base64.b64encode("tP$sa7Ml".encode("ascii")).decode("ascii"))
def rand0():
    t = permut("1234",4)
    return secrets.choice(list(t))
print("".join(rand0()))