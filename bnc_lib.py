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


def my_guess(game_info):
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
    game_info.my_history_list.append((game_info.guess_proposal, my_cows, my_bulls))
    if my_cows == capacity and my_bulls == capacity:
        # raise FinishedOKException
        return True
    if my_cows == 0 and my_bulls == 0:
        for a in game_info.guess_proposal:
            game_info.available_digits_str = game_info.available_digits_str.replace(a, '')
        if len(game_info.total_set) > 0:
            for c in list(game_info.total_set):
                for cc in game_info.guess_proposal:
                    if cc in c:
                        game_info.total_set.remove(c)
                        break
            if len(game_info.total_set) == 0:
                raise FinishedNotOKException
            game_info.guess_proposal = choice(tuple(game_info.total_set))
        else:
            game_info.guess_proposal = get_new_guess_proposal(game_info.capacity, game_info.guess_proposal)
        game_info.attempts += 1
        return False
    templates_set = game_info.get_templates()
    if my_cows == capacity:
        lst = ["".join(x) for x in templates_set]
    else:
        items_for_templates = game_info.get_items_for_templates()
        lst = [populate_template(a, b) for a in templates_set for b in items_for_templates]
    game_info.current_set = set(lst)
    if len(game_info.total_set) > 0:
        game_info.total_set = game_info.total_set & game_info.current_set
    else:
        game_info.total_set = game_info.current_set.copy()
    # game_info.write_set()
    if len(game_info.total_set) == 0:
        raise FinishedNotOKException
    game_info.guess_proposal = choice(tuple(game_info.total_set))
    game_info.attempts += 1
    game_info.current_set.clear()
    return False


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



