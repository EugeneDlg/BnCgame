import unittest
from BnC_Tk import Game

class TestGame(unittest.TestCase):
    def setUp(self):
        self.game = Game()

    def test_get_template(self):
        # not for my_cows == 0
        def get_template(cows: int, bulls: int, guess_proposal: str):
            game = self.game
            game.guess_proposal = guess_proposal
            game.capacity = capacity = len(guess_proposal)
            interim_str = ["V" for _ in range(capacity)]
            game.my_cows = cows
            game.my_bulls = bulls
            game.current_set = set()
            v_list = game.get_v_list()
            game.get_template(0 ,0, 0, 0, capacity, interim_str, v_list)
            total_list = sorted(game.current_set)
            # path = "bnc_ref_list_" + str(guess_proposal) + "_" + str(cows) + "_" + str(bulls)
            # with open(path,"w") as f:
            #     for i in total_list:
            #         f.write(i+'\n')
            return set(total_list)

        def get_correct_set(cows: int, bulls: int, guess_proposal: str):
            path = "bnc_ref_list_" + str(guess_proposal) + "_" + str(cows) + "_" + str(bulls)
            with open(path,"r") as f:
                file_str = f.read()
            file_list = file_str.split('\n')
            file_list.remove("")
            file_set = set(file_list)
            return file_set

        ref_list = [{'cows': 1, 'bulls': 0, 'guess_proposal': '1234'},
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
                    {'cows': 4, 'bulls': 0, 'guess_proposal': '1357'}]

        for i in ref_list:
            self.assertEqual(get_template(**i), get_correct_set(**i))

unittest.main()