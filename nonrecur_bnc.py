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


# t = [('v','1','v','v'),('v','v','2','v'),('v','3','v','v'),('2','v','v','v')]
# t0 = ('1','v','v','v')
# t1 = ('v','2','v','v')
#
# # print(next(filter(lambda e: e.isnumeric(),t1)) in t0)
#

#
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
# [print(e) for e in total]
#
# if not cows:
#     exit()
# if bulls > 0:


def overlap_set_items(a0, a1):
    lst = []
    for x in zip(a0, a1):
        if x[0].isnumeric() and x[1].isnumeric():
            return None
        lst.append(x[0] if x[0].isnumeric() else x[1])
    digits = list(filter(lambda e: e.isnumeric(), lst))
    if len(digits) != len(set(digits)):
        return None
    else:
        return lst


def overlap_sets(set0, set1, iteration):
    # for i0, c0 in enumerate(list0):
    #     for i1 in range(i0 + 1, len(list1)):
    #         tmp = list(map(overlap_set_items, zip(c0, list1[i1])))
    #         if tmp:
    #             total.append(tuple(tmp))
    total = set()
    while iteration > 0:
        total.clear()
        for i0 in set0:
            for i1 in set1:
                if i0 == i1:
                    continue
                tmp = overlap_set_items(i0, i1)
                if tmp:
                    total.add(tuple(tmp))
        set1 = total.copy()
        iteration -= 1
    return total

def get_all_variants():
    if cows - bulls == 0:
        bulls_permut = set(map(tuple, map(sorted, permutations(range(len(current_guess)), cows))))
        for i0 in bulls_permut:
            temp = ["V" for _ in range(capacity)]
            for i1 in i0:
                temp[i1] = current_guess[i1]
            only_bulls_set.add(tuple(temp))
        total = only_bulls_set.copy()

    else:
        one_bull_set = set()
        one_cow_set = set()
        for i0 in range(capacity):
            temp = ["V" for _ in range(capacity)]
            for i1, c1 in enumerate(guess_list):
                if i1 == i0:
                    continue
                temp[i0] = c1
                one_cow_set.add(tuple(temp))

        if cows - bulls == 1:
            total = one_cow_set.copy()
        else:
            total = overlap_sets(one_cow_set, one_cow_set, cows-bulls-1)
        if bulls > 0:
            bulls_permut = set(map(tuple, map(sorted, permutations(range(len(current_guess)), bulls))))
            for i0 in bulls_permut:
                temp = ["V" for _ in range(capacity)]
                for i1 in i0:
                    temp[i1] = current_guess[i1]
                only_bulls_set.add(tuple(temp))
            total = overlap_sets(only_bulls_set, total, 1)
    return total

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



