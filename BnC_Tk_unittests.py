import unittest
from BnC_Tk import Game

class TestGame(unittest.TestCase):
    def setUp(self):
        self.game = Game()

    def test_get_templates(self):
        # not for my_cows == 0

        def get_templates(cows: int, bulls: int, guess_proposal: str):
            game = self.game
            game.guess_proposal = guess_proposal
            game.capacity = capacity = len(guess_proposal)
            game.my_cows = cows
            game.my_bulls = bulls
            game.current_set = set()
            templates = game.get_templates()
            templates_list = sorted(templates)
            path = "test_get_templates_" + str(guess_proposal) + "_" + str(cows) + "_" + str(bulls)
            with open(path,"w") as f:
                for i in templates_list:
                    f.write(str("".join(i))+'\n')
            return set(templates_list)

        def get_correct_set(cows: int, bulls: int, guess_proposal: str):
            path = "test_get_templates_" + str(guess_proposal) + "_" + str(cows) + "_" + str(bulls)
            with open(path,"r") as f:
                file_str = f.read()
            file_str = file_str.rstrip("\n")
            file_list = file_str.split('\n')
            file_set = set(map(tuple,file_list))
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
                    {'cows': 4, 'bulls': 0, 'guess_proposal': '1357'},
                    {'cows': 2, 'bulls': 1, 'guess_proposal': '09876'},
                    {'cows': 3, 'bulls': 0, 'guess_proposal': '09876'},
                    {'cows': 3, 'bulls': 1, 'guess_proposal': '09876'},
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
            self.assertEqual(get_templates(**i), get_correct_set(**i))

unittest.main()