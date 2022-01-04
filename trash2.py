from itertools import permutations as permut
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
a = "1"
print(id(a))
a = "2"
print(id(a))
class A:
    pass

class B:
    pass

A.x = "3"
B.y = A.x
B.y = "4"
print(A.x)
print(B.y)
