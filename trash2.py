from itertools import permutations as permut
import secrets
import re
import base64
# print(base64.b64encode("bncuser_password".encode("ascii")).decode("ascii"))

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
#
# [print(i) for i in perm_lst]
d = {"a":1, "b":2, "c":3}
f0,f1,f2 = d
print(f0)



