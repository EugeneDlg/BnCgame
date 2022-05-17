from secrets import choice
from itertools import permutations
import random


def get_new_guess_proposal(capacity: int, guess_proposal='') -> str:
    new_guess_proposal = ''
    while len(new_guess_proposal) < capacity:
        c = str(random.randint(0, 9))
        if (not (c in guess_proposal)) and (not (c in new_guess_proposal)):
            new_guess_proposal += c
    return new_guess_proposal


def think_of_number_for_you(capacity):
    return "".join(choice(list(permutations("0123456789", capacity))))




# def get_user_by_login(login):
#     try:
#         session = Game.get_db_session(Game.default_db_user, Game.default_db_password)
#         r0 = session.query(BnCUsers).filter_by(login=login).first()
#         session.close()
#     except Exception:
#         try:
#             session.rollback()
#         except:
#             pass
#         raise
#     return r0



