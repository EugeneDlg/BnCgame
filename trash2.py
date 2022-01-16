from itertools import permutations as permut
import secrets

# "UWV0dTEyMyE="
# import re
# import base64
#
#
# def base64_decode_(encoded_string):
#     return base64.b64decode(encoded_string.encode("ascii")).decode("ascii")
#
# DB_CONN_STRING0 = "postgresql+psycopg2://postgres:tP$sa7Ml@127.0.0.1:5432/bnc"
# DB_CONN_STRING = "postgresql+psycopg2://postgres:dFAkc2E3TWw=@127.0.0.1:5432/bnc"
# m = re.search(r":([^/].+)@", DB_CONN_STRING)
# gg = DB_CONN_STRING.replace(m.group(1), base64_decode_(m.group(1)))
# print(DB_CONN_STRING)
# print(gg)
#
# print(base64.b64encode("tP$sa7Ml".encode("ascii")).decode("ascii"))


# def ExitApp():
#     MsgBox = messagebox.askquestion('Exit App', 'Really Quit?', icon='error')
#     if MsgBox == 'yes':
#         root.destroy()
#     else:
#         messagebox.showinfo('Welcome Back', 'Welcome back to the App')
#
#
# buttonEg = tk.Button(root, text='Exit App', command=ExitApp)
# buttonEg1 = tk.Button(root, text='AA', command=lambda: print("AA"))
# buttonEg.pack()
# buttonEg1.pack()


import tkinter


class Example(tkinter.Frame):
    def __init__(self, parent):
        tkinter.Frame.__init__(self, parent)
        self.canvas = tkinter.Canvas(self, borderwidth=0, background="#ffffff")
        self.frame = tkinter.Frame(self.canvas, background="#ffffff")
        self.vsb = tkinter.Scrollbar(self, orient="vertical", command=self.canvas.yview)
        self.canvas.configure(yscrollcommand=self.vsb.set)

        self.vsb.pack(side="right", fill="y")
        self.canvas.pack(side="left", fill="both", expand=True)
        self.canvas.create_window((4,4), window=self.frame, anchor="nw",
                                  tags="self.frame")

        self.frame.bind("<Configure>", self.onFrameConfigure)

        self.populate()

    def populate(self):
        '''Put in some fake data'''
        for row in range(100):
            tkinter.Label(self.frame, text="%s" % row, width=3, borderwidth="1",
                     relief="solid").grid(row=row, column=0)
            t="this is the second column for row %s" %row
            tkinter.Label(self.frame, text=t).grid(row=row, column=1)

    def onFrameConfigure(self, event):
        '''Reset the scroll region to encompass the inner frame'''
        self.canvas.configure(scrollregion=self.canvas.bbox("all"))

if __name__ == "__main__":
    root=tkinter.Tk()
    sub_root = tkinter.Toplevel(root)
    example = Example(sub_root)
    example.pack(side="top", fill="both", expand=True)
    sub_root.transient(root)
    sub_root.grab_set()
    sub_root.focus_set()
