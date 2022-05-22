from secrets import choice
from itertools import permutations
import random


def get_my_first_guess(capacity: int, guess='') -> str:
    new_guess = ''
    while len(new_guess) < capacity:
        c = str(random.randint(0, 9))
        if (not (c in guess)) and (not (c in new_guess)):
            new_guess += c
    return new_guess


def think_of_number_for_you(capacity):
    return "".join(choice(list(permutations("0123456789", capacity))))


def generate_my_guess(game_info):
    """
    The method figures out my next guess proposal based on number
    of cows and bulls that were given by you (user) for my current guess proposal.
    :param game_info
    :return: - True if the original number is guessed my me (by the script), i.e.
                    my_cows == my_bulls == capacity. So I am a winner.
             - False if everything is OK and so we can proceed the game to the next iteration.
                    I calculate the next guess proposal based on my_cows and my_bulls.
             - FinishedNotOKException raised if you have misled me during previous game iteration
             by providing of wrong cows and/or bulls. In this case game
             has become inconsistent, so I cannot guess your number and so I have to finish the game.
    """

    def populate_template(a, b):
        """
        The method replace a vacant place (letter 'V') in 'a' agrument (a template) with a digit from
        b argument consequently. So it makes one possible guess number for guess numbers set.
        :param a: a template with 'V's and digits from the guess number
        :param b: digits which will be put instead of 'V'
        :return: one possible guess number for guess numbers set
        """
        list0 = list(a)
        list1 = []
        list1.extend(b)
        while list0.count('V'):
            list0[list0.index('V')] = list1.pop()
        return "".join(list0)

    capacity = game_info.capacity
    my_cows = game_info.my_cows
    my_bulls = game_info.my_bulls
    game_info.my_history_list.append((game_info.my_guess, my_cows, my_bulls))
    print(isinstance(capacity, int))
    print(isinstance(my_bulls, int))
    print(isinstance(game_info.my_history_list, list))
    return
    if my_cows == capacity and my_bulls == capacity:
        return True
    if my_cows == 0 and my_bulls == 0:
        for a in game_info.my_guess:
            game_info.available_digits_str = game_info.available_digits_str.replace(a, '')
        if len(game_info.total_set) > 0:
            for c in list(game_info.total_set):
                for cc in game_info.my_guess:
                    if cc in c:
                        game_info.total_set.remove(c)
                        break
            if len(game_info.total_set) == 0:
                raise FinishedNotOKException
            game_info.my_guess = choice(tuple(game_info.total_set))
        else:
            game_info.my_guess = get_my_first_guess(game_info.capacity, game_info.my_guess)
        game_info.attempts += 1
        return False
    templates_set = game_info.get_templates()
    if my_cows == capacity:
        lst = ["".join(x) for x in templates_set]
    else:
        items_for_templates = game_info.get_items_for_templates()
        lst = [populate_template(a, b) for a in templates_set for b in items_for_templates]
    current_set = set(lst)
    if len(game_info.total_set) > 0:
        game_info.total_set = game_info.total_set & current_set
    else:
        game_info.total_set = current_set.copy()
    # game_info.write_set()
    if len(game_info.total_set) == 0:
        raise FinishedNotOKException
    game_info.my_guess = choice(tuple(game_info.total_set))
    game_info.attempts += 1
    return False


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
        return tuple(lst)


def overlap_sets(set0, set1, iteration):
    total = set()
    while iteration > 0:
        total.clear()
        sss = (overlap_set_items(a, b) for a in set0 for b in set1)
        total = set(sss)
        total.discard(None)
        # total = set(filter(lambda s: s is not None, sss))
        set1 = total.copy()
        iteration -= 1
    return total


def get_items_for_templates(cows, capacity, guess, init_rest_str="0123456789"):
    items_for_templates = []
    for a in guess:
        init_rest_str = init_rest_str.replace(a, '')
    if capacity - cows > 0:
        for l in permutations(init_rest_str, capacity - cows):
            items_for_templates.append(''.join(map(str, l)))
    return items_for_templates


def get_templates(cows, bulls, current_guess, capacity):
    only_bulls_set = set()
    one_cow_set = set()
    total = set()
    if cows == bulls:
        bulls_permut = set(map(tuple, map(sorted, permutations(range(len(current_guess)), cows))))
        for i0 in bulls_permut:
            temp = ["V" for _ in range(capacity)]
            for i1 in i0:
                temp[i1] = current_guess[i1]
            only_bulls_set.add(tuple(temp))
        total = only_bulls_set.copy()
    else:
        for i0 in range(capacity):
            temp = ["V" for _ in range(capacity)]
            for i1, c1 in enumerate(current_guess):
                if i1 == i0:
                    continue
                temp[i0] = c1
                one_cow_set.add(tuple(temp))
        if cows - bulls == 1:
            total = one_cow_set.copy()
        else:
            total = overlap_sets(one_cow_set, one_cow_set, cows - bulls - 1)
        if bulls > 0:
            bulls_permut = set(map(tuple, map(sorted, permutations(range(len(current_guess)), bulls))))
            for i0 in bulls_permut:
                temp = ["V" for _ in range(capacity)]
                for i1 in i0:
                    temp[i1] = current_guess[i1]
                only_bulls_set.add(tuple(temp))
            total = overlap_sets(only_bulls_set, total, 1)
    return total


class UserNotFoundException(Exception):
    pass


class InvalidLoginException(Exception):
    def __init__(self, a):
        super().__init__()
        self.msg = "User with this login doesn't exist!" if a else "User with this login already exists!"

    def __repr__(self):
        return "{}".format(self.msg)

    def __str__(self):
        return "{}".format(self.msg)


class FinishedOKException(Exception):
    pass


class FinishedNotOKException(Exception):
    pass


class NoAdminException(Exception):
    pass


class IncorrectPasswordException(Exception):
    def __repr__(self):
        return "Incorrect Password!"

    def __str__(self):
        return "Incorrect Password!"


class IncorrectDBPasswordException(Exception):
    def __repr__(self):
        return "Incorrect DB password for your user! Please ask DB administrator for help."

    def __str__(self):
        return "Incorrect DB password for your user! Please ask DB administrator for help."



