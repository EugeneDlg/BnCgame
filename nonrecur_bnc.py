from itertools import permutations
from BnC_Tk import Game

game = Game()
current_guess = game.guess_proposal = "1234"
capacity = game.capacity = len(current_guess)
cows = game.my_cows = 4
bulls = game.my_bulls = 1
guess_list = []
guess_list.extend(current_guess)
tpl = (guess_list)
one_cow_list = set()
only_bulls_set = set()



# # print((list(map(overlap, zip(t0,t1)))))
# list1 = one_cow_list.copy()
# list2 = one_cow_list.copy()
# total = []
# for i0, c0 in enumerate(list1):
#     for i1 in range(i0+1, len(list2)):
#         tmp = list(map(overlap, zip(c0, list2[i1])))
#         is_found = next(filter(lambda e: e.isnumeric(), c0)) in list2[i1]
#         if not is_found and all(tmp):
#             total.append(tmp[:])
#


# total_s = sorted(total)
# [print("".join(map(str,x))) for x in total_s]

v_list = game.get_v_list()
total = get_all_variants()
for x in total:
    s = game.populate(x, v_list)
    game.current_set = game.current_set | s
total_list_non = sorted(game.current_set)
# print(total_list_non)

interim_str = ["V" for _ in range(capacity)]
game.current_set = set()
game.get_template(0, 0, 0, 0, capacity, interim_str, v_list)
total_list_recur = sorted(game.current_set)
print(len(total_list_recur))
print(len(total_list_non))
print(total_list_recur==total_list_non)



