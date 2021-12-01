# class Nole():
#     def __init__(self):
#         self.capacity = None
#         print("Nole!")
#
#
# class Game1(Nole):
#     def __init__(self):
#         super(Game1, self).__init__()
#         print("game1")
#         self.x = 8
#         self.capacity = 6
#         self.attempts = 0
#         self.previous_all_set = set()
#         self.available_digits_str = '0123456789'
#
#
# class Tk1(Nole):
#     def __init__(self):
#         super(Tk1, self).__init__()
#
#         print("tk1")
#         self.title = "NNN"
#
#
# class MainWin(Tk1, Game1):
#     def __init__(self):
#         print("MainWin 1")
#         super(MainWin, self).__init__()
#         print("MainWin 2")
#         self.initial_main_height = 200
#         self.initial_main_width = 470
#         self.button = None
#         self.lb0 = None
#         self.lb4 = None
#         self.lb3_ = None
#         self.text1 = None
#         self.text2 = None
#
# mw = MainWin()
# print(mw.capacity)

# class machine(object):
#
#     def __init__(self):
#         print ("I am in constructor of machine class")
#         print("machine post")
#
#
# class computer():
#     def __init__(self):
#         print ("I am in constructor of computer class")
#         name = 1
#         # super(computer,self).__init__()
#         print("computer post")
#
#
# class computer_sub(computer):
#     def __init__(self):
#         print("sub")
#         super(computer, self).__init__()
#         print("sub post")
#
# class laptop(machine):
#     def __init__(self):
#         self.x = 99
#         print ("I am in constructor of laptop class")
#         super(laptop,self).__init__()
#         print("laptop post")
#
#
# class respbarry(computer_sub,laptop):
#     def __init__(self):
#         print ("I am in constructor of respbarry class")
#         super(respbarry,self).__init__()
#         print("raspberyy post")
#
#
# r = respbarry()
# print(r.x)


class B():
    def __init__(self):
        print("B")


class C():
    def __init__(self):
        print("C")
        # super(C, self).__init__()
        B.__init__(self)



class D(C):
    def __init__(self):
        print("D")
        super().__init__()


d = D()