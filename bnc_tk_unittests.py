import unittest
from bnc_tk import Game, FinishedNotOKException
from secrets import choice
from random import random, randint

CONFIG_PATH = "bnc_config.yml"


class TestGame(unittest.TestCase):
    def setUp(self):
        self.game = Game()
        # D stands for digits, U - uppercase latters, L - lowercase latters
        self.test_login = self.get_random_name("DUL", 4)
        self.test_first_name = self.get_random_name("DUL", 5)
        self.test_last_name = self.get_random_name("DUL", 6)
        self.test_password = self.get_random_name("DUL", 10)
        self.test_email = (self.get_random_name("DUL", 5)
                           + "@" + self.get_random_name("DUL", 3)
                           + ".com")

    @staticmethod
    def get_random_name(data_types, length):
        lst = list()
        if "D" in data_types:
            lst.append((48, 57))
        if "U" in data_types:
            lst.append((65, 90))
        if "L" in data_types:
            lst.append((97, 122))
        return "".join([chr(randint(*choice(lst))) for _ in range(length+1)])

    def test_get_templates(self):

        # not for my_cows == 0 and my_bulls == 0 (case 0.0). This case is processed in my_guess method
        def get_templates(cows: int, bulls: int, guess_proposal: str):
            game = self.game
            game.guess_proposal = guess_proposal
            game.capacity = capacity = len(guess_proposal)
            game.my_cows = cows
            game.my_bulls = bulls
            game.current_set = set()
            templates = game.get_templates()
            templates_list = sorted(templates)
            # path = "test_get_templates_" + str(guess_proposal) + "_" + str(cows) + "_" + str(bulls)
            # with open(path,"w") as f:
            #     for i in templates_list:
            #         f.write(str("".join(i))+'\n')
            return set(templates_list)

        def get_correct_set(cows: int, bulls: int, guess_proposal: str):
            path = "test_get_templates_" + str(guess_proposal) + "_" + str(cows) + "_" + str(bulls)
            with open(path, "r") as f:
                file_str = f.read()
            file_str = file_str.rstrip("\n")
            file_list = file_str.split('\n')
            file_set = set(map(tuple, file_list))
            return file_set

        ref_list = [{'cows': 1, 'bulls': 0, 'guess_proposal': '012'},
                    {'cows': 1, 'bulls': 1, 'guess_proposal': '012'},
                    {'cows': 2, 'bulls': 0, 'guess_proposal': '012'},
                    {'cows': 2, 'bulls': 1, 'guess_proposal': '012'},
                    {'cows': 2, 'bulls': 2, 'guess_proposal': '012'},
                    {'cows': 3, 'bulls': 0, 'guess_proposal': '012'},
                    {'cows': 3, 'bulls': 1, 'guess_proposal': '012'},
                    {'cows': 1, 'bulls': 0, 'guess_proposal': '1234'},
                    {'cows': 2, 'bulls': 1, 'guess_proposal': '1234'},
                    {'cows': 3, 'bulls': 0, 'guess_proposal': '1234'},
                    {'cows': 3, 'bulls': 1, 'guess_proposal': '1234'},
                    {'cows': 3, 'bulls': 3, 'guess_proposal': '1234'},
                    {'cows': 4, 'bulls': 0, 'guess_proposal': '1234'},
                    {'cows': 4, 'bulls': 1, 'guess_proposal': '1234'},
                    {'cows': 4, 'bulls': 2, 'guess_proposal': '1234'},
                    {'cows': 1, 'bulls': 1, 'guess_proposal': '0987'},
                    {'cows': 2, 'bulls': 2, 'guess_proposal': '0987'},
                    {'cows': 3, 'bulls': 3, 'guess_proposal': '0987'},
                    {'cows': 2, 'bulls': 1, 'guess_proposal': '0987'},
                    {'cows': 3, 'bulls': 1, 'guess_proposal': '0987'},
                    {'cows': 4, 'bulls': 1, 'guess_proposal': '0987'},
                    {'cows': 1, 'bulls': 0, 'guess_proposal': '1357'},
                    {'cows': 2, 'bulls': 0, 'guess_proposal': '1357'},
                    {'cows': 3, 'bulls': 0, 'guess_proposal': '1357'},
                    {'cows': 4, 'bulls': 0, 'guess_proposal': '1357'},
                    {'cows': 2, 'bulls': 1, 'guess_proposal': '09876'},
                    {'cows': 3, 'bulls': 0, 'guess_proposal': '09876'},
                    {'cows': 3, 'bulls': 1, 'guess_proposal': '09876'},
                    {'cows': 3, 'bulls': 3, 'guess_proposal': '09876'},
                    {'cows': 4, 'bulls': 0, 'guess_proposal': '09876'},
                    {'cows': 4, 'bulls': 1, 'guess_proposal': '09876'},
                    {'cows': 4, 'bulls': 2, 'guess_proposal': '09876'},
                    {'cows': 4, 'bulls': 3, 'guess_proposal': '09876'},
                    {'cows': 5, 'bulls': 0, 'guess_proposal': '09876'},
                    {'cows': 5, 'bulls': 2, 'guess_proposal': '09876'},
                    {'cows': 5, 'bulls': 3, 'guess_proposal': '09876'},
                    {'cows': 2, 'bulls': 0, 'guess_proposal': '345678'},
                    {'cows': 3, 'bulls': 1, 'guess_proposal': '345678'},
                    {'cows': 3, 'bulls': 3, 'guess_proposal': '345678'},
                    {'cows': 4, 'bulls': 2, 'guess_proposal': '345678'},
                    {'cows': 4, 'bulls': 4, 'guess_proposal': '345678'},
                    {'cows': 5, 'bulls': 0, 'guess_proposal': '345678'},
                    {'cows': 5, 'bulls': 3, 'guess_proposal': '345678'},
                    {'cows': 5, 'bulls': 5, 'guess_proposal': '345678'},
                    {'cows': 6, 'bulls': 0, 'guess_proposal': '345678'},
                    {'cows': 6, 'bulls': 1, 'guess_proposal': '345678'},
                    {'cows': 6, 'bulls': 3, 'guess_proposal': '345678'},
                    {'cows': 6, 'bulls': 4, 'guess_proposal': '345678'}]

        for i in ref_list:
            self.assertEqual(get_templates(**i), get_correct_set(**i))

    def test_my_guess(self):
        """
        This method is to verify special cases that are not covered by test_get_templates, i.e.
        cases when a user erraneously enters wrong cows and/or bulls so game is to be finished.
        """
        game = self.game
        test_list = [[{"8765", "9876", "0987"}, "1234", 1, 0, 1],
                     [{"4321"}, "1234", 0, 0, 1],
                     [{"1230", "0987"}, "4567", 4, 2, 2]
                     ]
        for a in test_list:
            game.total_set = a[0]
            game.guess_proposal = a[1]
            game.my_cows = a[2]
            game.my_bulls = a[3]
            game.attempts = a[4]
            self.assertRaises(FinishedNotOKException, game.my_guess)

    def test_read_config(self):
        game = self.game
        game.read_config()

    def test_get_user_by_login(self):
        game = self.game
        login = self.test_login
        user_data = game.get_user_by_login(login)
        self.assertIsNone(user_data)

    # def test_load_logged_user_info(self):
    #     game = self.game
    #     user = "admin"
    #     user_data = Game.load_logged_user_info(user)
    #     self.assertIsNotNone(user_data)

    def test_validate_db_role_before(self):
        game = self.game
        ret_val = game.validate_db_user(self.test_login, "create")
        self.assertIsNone(ret_val)

    def test_create_db_user(self):
        game = self.game
        login = self.test_login
        password = self.test_password
        ret_val = game.create_db_user(login, password)
        self.assertIsNone(ret_val)

    def test_validate_db_role_after(self):
        game = self.game
        ret_val = game.validate_db_user(self.test_login, "other")
        self.assertIsNone(ret_val)

    # def test_validate_user(self):
    #     game = self.game
    #     login = self.test_login
    #     first_name = self.test_first_name
    #     last_name = self.test_last_name
    #     password = self.test_password
    #     email = self.test_email
    #     args = login, password, password, first_name, last_name, email
    #     ret_val = game.validate_user(*args, op="create")
    #     self.assertIsNone(ret_val)

    # def test_create_user(self):
    #     game = self.game
    #     login = self.test_login
    #     first_name = self.test_first_name
    #     last_name = self.test_last_name
    #     password = self.test_password
    #     email = self.test_email
    #     args = login, password, first_name, last_name, email, db_user
    #     game.create_user()


unittest.main()
