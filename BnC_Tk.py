import base64
import random
import re
import tkinter
from tkinter import *
import itertools
import psycopg2
from sqlalchemy import Column, ForeignKey, Integer, String, Boolean, Date
from sqlalchemy import create_engine, inspect
from sqlalchemy.engine.reflection import Inspector
from sqlalchemy.orm import sessionmaker
from sqlalchemy.exc import NoSuchTableError, SQLAlchemyError, DatabaseError
from sqlalchemy.orm.session import close_all_sessions
import smtplib
import ssl
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
# from sqlalchemy.orm import relationship
from sqlalchemy.ext.declarative import declarative_base
from passlib.context import CryptContext

# DB_CONN_STRING = "postgresql+psycopg2://bncuser@127.0.0.1:5432/bnc"
DB_CONN_STRING = "postgresql+psycopg2://postgres:amkiqn3a@127.0.0.1:5432/bnc"
USERS_TABLE = "users"
PRIV_TABLE = "privileges"
ADMIN_USER = "admin"
SSL_PORT = 465
SMTP_ADDRESS = "smtp.gmail.com"
BNC_EMAIL = "Bulls.And.Cows.0@gmail.com"
Base = declarative_base()


class BnCUsers(Base):
    __tablename__ = USERS_TABLE
    id = Column(Integer, primary_key=True, nullable=False)
    login = Column(String, unique=True, nullable=False)
    firstname = Column(String, nullable=False)
    lastname = Column(String, nullable=False)
    email = Column(String, unique=True, nullable=False)
    password = Column(String, nullable=False)

    def __repr__(self):
        return "<User(login='{}', firstname='{}', lastname='{}', email='{}', password='{}')>" \
            .format(self.login, self.firstname, self.lastname, self.email, self.password)


class Privileges(Base):
    __tablename__ = PRIV_TABLE
    id = Column(Integer, primary_key=True, nullable=False)
    login = Column(String, ForeignKey(USERS_TABLE + ".login"), nullable=False)
    create_other = Column(Boolean, nullable=False)
    modify_self = Column(Boolean, nullable=False)
    modify_other = Column(Boolean, nullable=False)
    delete_self = Column(Boolean, nullable=False)
    delete_other = Column(Boolean, nullable=False)

    def __repr__(self):
        return "<User(login='{}', create_other='{}', modify_self='{}', " \
               "modify_other='{}', delete_self='{}', delete_other='{}')>" \
            .format(self.login, self.create_other, self.modify_self,
                    self.modify_other, self.delete_self, self.delete_other)


# class Class:
#     pass


class Game():
    session = None
    engine = None
    text_for_restoring_password = """\
    Subject: Restoring your password

    Hello dear customer!
    Your pincode for password recovering: PINCODE
    Thank you for contacting us. Have a nice day!
    """
    html_for_restoring_password = """\
    <html>
      <body>
        <p><h3>Hello dear customer!</h3><br>
           We have received a request from you to recover your password.<br>
           Your pincode for password recovery: <h4>PINCODE<h/4><br><br>
           Thank you for contacting us. Have a nice day!<br>
            -- Best regards, BnC team. 
        </p>
      </body>
    </html>
    """

    def __init__(self, capacity=4):
        super().__init__()
        self.capacity = capacity
        self.attempts = 0
        self.previous_all_set = set()
        self.available_digits_str = '0123456789'
        self.proposed_str = ''
        self.proposed_strings_list = list()
        self.totqty_resp = None
        self.rightplace_resp = None
        self.your_string = None
        # self.initial_main_height = 200
        # self.initial_main_width = 470



        self.restore_window_width = 350
        self.restore_window_height = 180

        self.string_interval_history_frame = 22
        self.new_game_requested = False
        self.game_started = False
        self.loggedin_user = None
        self.admin_needed = False
        self.main_win = None
        self.menubar = None
        self.filemenu = None
        self.helpmenu = None
        self.lb0 = None
        self.lb1 = None
        self.text1 = None
        self.lb2 = None
        self.text2 = None
        self.button = None
        self.lb3_ = None
        self.fr0 = None
        self.lb4 = None
        self.your_string_entry = None
        self.user_privileges = None

        self.setting_window = None
        self.help_window = None
        self.login_window = None
        self.login_window_lb0 = None
        self.setting_window_cap_lb = None
        self.setting_window_cap_en = None
        self.setting_window_cap_bt = None
        self.setting_window_lf0 = None
        self.setting_window_lf1 = None
        self.setting_window_un_lb = None
        self.setting_window_un_en = None
        self.setting_window_pw_lb = None
        self.setting_window_pw_en = None
        self.setting_window_cr_bt = None
        self.setting_window_dl_bt = None
        self.about_lb1 = None
        self.proposed_strings_lb_list = list()
        self.users_window = None
        self.users_window_login_lb = None
        self.users_window_login_en = None
        self.users_window_pass_lb = None
        self.users_window_pass_en = None
        self.users_window_firstname_lb = None
        self.users_window_firstname_en = None
        self.users_window_lastname_lb = None
        self.users_window_lastname_en = None
        self.users_window_pass_lb1 = None
        self.users_window_pass_en1 = None
        self.users_window_pass_lb2 = None
        self.users_window_pass_en2 = None
        self.password_en1 = None
        self.password_en2 = None
        self.users_window_create_bt = None
        self.users_window_delete_bt = None
        self.users_window_modify_bt = None
        self.users_window_show_pass_bt = None
        self.users_window_email_lb = None
        self.users_window_email_en = None
        self.login_window_rp_bt = None
        self.pincode = None

    @staticmethod
    def encrypt_password(password):
        context = CryptContext(
            schemes=["pbkdf2_sha256"],
            default="pbkdf2_sha256",
            pbkdf2_sha256__default_rounds=30000
        )
        return context.hash(password)

    @staticmethod
    def check_password(password, hashed):
        context = CryptContext(
            schemes=["pbkdf2_sha256"],
            default="pbkdf2_sha256",
            pbkdf2_sha256__default_rounds=30000
        )
        try:
            r = context.verify(password, hashed)
        except Exception as err:
            return ResponseMsg(str(err), "error")
        if not r:
            return ResponseMsg("Incorrect password", "error")

    def send_pincode(self, email):
        # return
        password = base64.b64decode("UWV0dTEyMyE=".encode("ascii")).decode("ascii")
        email_msg = MIMEMultipart("alternative")
        sender_email = BNC_EMAIL
        receiver_email = "stayerx@gmail.com"
        email_msg["Subject"] = "Restoring your password"
        email_msg["From"] = sender_email
        email_msg["To"] = receiver_email
        self.pincode = str(random.randint(1000, 9999))
        self.text_for_restoring_password = self.text_for_restoring_password.replace(
            "PINCODE", str(self.pincode)
        )
        self.html_for_restoring_password = self.html_for_restoring_password.replace(
            "PINCODE", str(self.pincode)
        )
        p1 = MIMEText(self.text_for_restoring_password, "plain")
        p2 = MIMEText(self.html_for_restoring_password, "html")
        email_msg.attach(p1)
        email_msg.attach(p2)
        context = ssl.create_default_context()
        with smtplib.SMTP_SSL(SMTP_ADDRESS, SSL_PORT, context=context) as srv:
            srv.login(BNC_EMAIL, password)
            srv.sendmail(sender_email, receiver_email, email_msg.as_string())

    @staticmethod
    def validate_pincode(entered_pincode, correct_pincode):
        if not entered_pincode.isnumeric():
            return ResponseMsg("Pin code must contain only digits", "error")
        if correct_pincode != entered_pincode:
            return ResponseMsg("Incorrect pincode", "error")

    @staticmethod
    def populate(interim_str, v_list, attempt_set):
        if interim_str.count('V') == 0:
            attempt_set.add(''.join(interim_str))
        else:
            for y in v_list:
                i = 0
                a = ''
                for z in interim_str:
                    if z == "V":
                        a += y[i]
                        i += 1
                    else:
                        a += z
                attempt_set.add(a[:])
        return attempt_set

    def get_new_proposed_str(self):
        new_proposed_str = ''
        while len(new_proposed_str) < self.capacity:
            c = str(random.randint(0, 9))
            if (not (c in self.proposed_str)) and (not (c in new_proposed_str)):
                new_proposed_str += c
        self.proposed_str = new_proposed_str

    def get_template(self, ini0, ini1, iter0, iter1, ext_cycle_end, interim_str, v_list, attempt_set):
        for i0 in range(ini0, ext_cycle_end):
            if iter0 < self.rightplace_resp and iter1 == 0:
                if interim_str[i0] != 'V':
                    continue
                else:
                    interim_str[i0] = self.proposed_str[i0]
                if iter0 < self.rightplace_resp - 1:
                    iter0 += 1
                    self.get_template(i0 + 1, 0, iter0, iter1, ext_cycle_end, interim_str, v_list, attempt_set)
                    iter0 -= 1
                else:
                    if self.rightplace_resp == self.totqty_resp:
                        populate(interim_str, v_list, attempt_set)
            if (self.rightplace_resp - 1 <= iter0 < self.totqty_resp - 1) or self.rightplace_resp == 0:
                for i1 in range(ini1, len(self.proposed_str)):
                    if self.proposed_str[i1] in interim_str: continue
                    for i2, c in enumerate(self.proposed_str):
                        if i1 == i2:
                            continue
                        if interim_str[i2] != 'V':
                            continue
                        else:
                            interim_str[i2] = self.proposed_str[i1]
                        if iter1 < self.totqty_resp - self.rightplace_resp - 1:
                            iter1 += 1
                            self.get_template(0, i1 + 1, iter0, iter1, 1, interim_str, v_list, attempt_set)
                            iter1 -= 1
                            interim_str[i2] = 'V'
                        else:
                            interim_str[i2] = self.proposed_str[i1]
                            populate(interim_str, v_list, attempt_set)
                            interim_str[i2] = 'V'
            if iter1 == 0:
                interim_str[i0] = 'V'

    def calc_bulls_and_cows(self):
        totqty_resp = rightplace_resp = 0
        for i0, c0 in enumerate(self.your_string):
            for i1, c1 in enumerate(self.proposed_str):
                if c0 == c1:
                    totqty_resp += 1
                    if i0 == i1:
                        rightplace_resp += 1
                    break
        self.totqty_resp = totqty_resp
        self.rightplace_resp = rightplace_resp


    def new_guess(self):
        game = self.game
        capacity = game.capacity
        totqty_resp = game.totqty_resp
        rightplace_resp = game.rightplace_resp
        game.rightplace_resp
        attempt_set = set()
        if game.attempts == 0:
            game.get_new_proposed_str()
            game.attempts += 1
            self.change_proposed_str_on_window()
            return
        if not game.your_string:
            if not ((self.text1.get()).isdigit() and self.text2.get().isdigit()):
                return
            game.totqty_resp = int(self.text1.get())
            self.text1.delete(0, 'end')
            game.rightplace_resp = int(self.text2.get())
            self.text2.delete(0, 'end')
            totqty_resp = game.totqty_resp
            rightplace_resp = game.rightplace_resp
        if (totqty_resp == capacity and rightplace_resp == capacity - 1) or (
                rightplace_resp > totqty_resp) or rightplace_resp > capacity or totqty_resp > capacity:
            MessageBox.show_message(self,ResponseMsg(
                "Erroneous input combination! Try again!","error"))
            return #continue
        game.proposed_strings_list.append((game.proposed_str, totqty_resp, rightplace_resp))
        if totqty_resp == capacity and rightplace_resp == capacity:
            self.finish_game(len(game.previous_all_set), 'YAHOO!!! I Did it! Attempts: ' + str(game.attempts), '#00f')
            return
        if totqty_resp == 0 and rightplace_resp == 0:
            for a in self.proposed_str:
                self.available_digits_str = self.available_digits_str.replace(a, '')
            if len(self.previous_all_set) > 0:
                for c in list(self.previous_all_set):
                    for cc in self.proposed_str:
                        if cc in c:
                            self.previous_all_set.remove(c)
                            break
                if len(self.previous_all_set) == 0:
                    self.finish_game(0, "You have broken my mind!!! Think of a new number now!", '#f00')
                    return
                r = random.randint(0, len(self.previous_all_set) - 1)
                for i, c in enumerate(self.previous_all_set):
                    if i == r: break
                self.proposed_str = c
            else:
                self.get_new_proposed_str()
            self.attempts += 1
            self.change_proposed_str_on_window()
            return
        interim_str = ["V" for a in range(self.capacity)]  # to_do
        init_rest_str = self.available_digits_str
        for a in self.proposed_str:
            init_rest_str = init_rest_str.replace(a, '')
        v_list = []
        if self.capacity - self.totqty_resp > 0:
            for l in itertools.permutations(init_rest_str, self.capacity - self.totqty_resp):
                v_list.append(''.join(map(str, l)))
        if self.rightplace_resp > 0:
            self.get_template(0, 0, 0, 0, self.capacity, interim_str, v_list, attempt_set)
        else:
            self.get_template(0, 0, 0, 0, 1, interim_str, v_list, attempt_set)
        if len(self.previous_all_set) > 0:
            self.previous_all_set = self.previous_all_set & attempt_set
        else:
            self.previous_all_set = attempt_set
        if len(self.previous_all_set) == 0:
            self.finish_game(0, "You have broken my mind!!! Think of a new number now!", '#f00')
            return
        r = random.randint(0, len(self.previous_all_set) - 1)
        for i, c in enumerate(self.previous_all_set):
            if i == r:
                break
        self.proposed_str = c
        self.attempts += 1
        self.change_proposed_str_on_window()



    @staticmethod
    def add_user(*args):
        login, password, firstname, lastname, email = args
        login = login.strip().lower()
        password = password.strip()
        firstname = firstname.strip()
        lastname = lastname.strip()
        email = email.strip().lower()
        user = BnCUsers(
            login=login,
            firstname=firstname,
            lastname=lastname,
            email=email,
            password=Game.encrypt_password(password)
        )
        try:
            session = Game.get_db_session()
            session.add(user)
            session.commit()
            session.close()
        except Exception as err:
            session.rollback()
            return ResponseMsg(str(err), "error")


    @staticmethod
    def modify_user(*args, only_password):
        if only_password:
            login, password = args
            login = login.strip().lower()
            password = password.strip()
        else:
            login, password, firstname, lastname, email = args
            login = login.strip().lower()
            password = password.strip()
            firstname = firstname.strip()
            lastname = lastname.strip()
            email = email.strip().lower()
        try:
            session = Game.get_db_session()
            if only_password:
                session.query(BnCUsers).filter_by(login=login).update({"login": login,
                                                                       "password": Game.encrypt_password(password)})
            else:
                session.query(BnCUsers).filter_by(login=login).update({"login": login,
                                                                       "firstname": firstname,
                                                                       "lastname": lastname,
                                                                       "email": email,
                                                                       "password": Game.encrypt_password(password)})
            session.commit()
            session.close()
        except Exception as err:
            session.rollback()
            return ResponseMsg(str(err), "error")

    @staticmethod
    def delete_user(login):
        login = login.strip().lower()
        try:
            session = Game.get_db_session()
            session.query(Privileges).filter_by(login=login).delete()
            session.query(BnCUsers).filter_by(login=login).delete()
            session.commit()
            session.close()
        except Exception as err:
            session.rollback()
            return ResponseMsg(str(err), "error")

    @staticmethod
    def get_db_session():
        if not Game.session:
            try:
                Game.engine = create_engine(DB_CONN_STRING)
                DBSession = sessionmaker(bind=Game.engine)
                Game.session = DBSession()
                return Game.session
            except Exception as err:
                return ResponseMsg(str(err), "error")
        return Game.session

    @staticmethod
    def validate_user(*args, op):
        ret_message = ""
        if op == "other" or op == "modify":
            if op == "modify":
                login, password1, password2, firstname, lastname, email = args
            else:
                login, = args
            login = login.strip().lower()
            s0_l = re.search(r'[^\w\-]', login)
            if 4 > len(login):
                ret_message += "Login is too short. "
            elif 20 < len(login):
                ret_message += "Login is too long. "
            elif s0_l:
                ret_message += "Login contains inappropriate symbols. "
            if ret_message:
                return ResponseMsg(ret_message, "error")
            r0 = Game.get_user_by_login(login)
            if not r0:
                return ResponseMsg("User with this login doesn't exist!", "error")
            if op == "other":
                return
        login, password1, password2, firstname, lastname, email = args
        login = login.strip().lower()
        password1 = password1.strip()
        password2 = password2.strip()
        firstname = firstname.strip()
        lastname = lastname.strip()
        email = email.strip().lower()
        s0_l = re.search(r'[^\w\-]', login)
        s0_em = re.search(r'[\w.+$%!?\'-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[a-z]{2,9}$', email)
        if 4 > len(login):
            ret_message += "Login is too short. "
        elif 20 < len(login):
            ret_message += "Login is too long. "
        elif s0_l:
            ret_message += "Login contains inappropriate symbols. "
        ret_message += Game.validate_password(password1, password2)
        if 1 > len(firstname):
            ret_message += "First name is too short. "
        elif 20 < len(firstname):
            ret_message += "First name is too long. "
        elif re.search(r'[^A-Za-z_-]', firstname):
            ret_message += "Incorrect first name. "
        if 1 > len(lastname):
            ret_message += "Last name is too short. "
        elif 20 < len(lastname):
            ret_message += "Last name is too long. "
        elif re.search(r'[^A-Za-z_-]', lastname):
            ret_message += "Incorrect last name. "
        if not s0_em:
            ret_message += "Incorrect e-mail. "
        if ret_message:
            return ResponseMsg(ret_message, "error")
        if op == "create":
            r0 = Game.get_user_by_login(login)
            session = Game.get_db_session()
            try:
                r1 = session.query(BnCUsers).filter_by(email=email).first()
                session.close()
            except Exception as err:
                session.rollback()
                return ResponseMsg(str(err), "error")
            if r0:
                ret_message += "User with this login already exists! "
            if r1:
                ret_message += "User with this e-mail already exists! "
            if ret_message:
                return ResponseMsg(ret_message, "error")

    @staticmethod
    def validate_password(password1, password2):
        ret_message = ""
        s0_p = re.search(r'[\W_]', password1)
        s1_p = re.search(r'[A-Z]', password1)
        s2_p = re.search(r'[a-z]', password1)
        s3_p = re.search(r'[\d]', password1)
        if password1 != password2:
            ret_message += "Passwords don't match. "
        elif 6 > len(password1):
            ret_message += "Password is too short. "
        elif 20 < len(password1):
            ret_message += "Password is too long. "
        elif s0_p is None or s1_p is None or s2_p is None or s3_p is None:
            ret_message += "Password must contain at least one capital letter, one lowercase letter, one digit " + \
                           "and one special symbol. "
        return ret_message

    @staticmethod
    def authenticate_user(login, password_entered):
        login = login.strip().lower()
        r_msg = Game.validate_user(login, op="other")
        if r_msg:
            return r_msg
        user_data = Game.get_user_by_login(login)
        if isinstance(user_data, ResponseMsg):
            return user_data  # We rerturn a ResponseClass instance with an error
        if not user_data:
            return ResponseMsg("User not found!", "error")
        # match = re.search(r"password=\'(.*)\'", str(r0))
        password_hashed = user_data.password
        r = Game.check_password(password_entered, password_hashed)
        return r

    @staticmethod
    def get_user_by_login(login):
        session = Game.get_db_session()
        try:
            r0 = session.query(BnCUsers).filter_by(login=login).first()
            session.close()
        except Exception as err:
            session.rollback()
            return ResponseMsg(str(err), "error")
        return r0

    def retrieve_user_privileges(self, login):
        try:
            session = Game.get_db_session()
            r0 = session.query(Privileges).filter_by(login=login).first()
            session.close()
        except Exception as err:
            session.rollback()
            return ResponseMsg(str(err), "error")
        self.user_privileges = {'create_other': r0.create_other, 'modify_self': r0.modify_self,
                                'modify_other': r0.modify_other, 'delete_self': r0.delete_self,
                                'delete_other': r0.delete_other}

    @staticmethod
    def create_user_privileges(login):
        if login == ADMIN_USER:
            user_priv = {"create_other": True, "modify_self": True, "modify_other": True,
                         "delete_self": False, "delete_other": True}
        else:
            user_priv = {"create_other": True, "modify_self": True, "modify_other": False,
                         "delete_self": True, "delete_other": False}
        privileges = Privileges(
            login=login,
            create_other=user_priv["create_other"],
            modify_self=user_priv["modify_self"],
            modify_other=user_priv["modify_other"],
            delete_self=user_priv["delete_self"],
            delete_other=user_priv["delete_other"]
        )
        session = Game.get_db_session()
        try:
            session.add(privileges)
            session.commit()
            session.close()
        except Exception as err:
            session.rollback()
            return ResponseMsg(str(err), "error")

    @staticmethod
    def delete_user_privileges(login):
        try:
            session = Game.get_db_session()
            r0 = session.query(Privileges).filter_by(login=login).delete()
            session.commit()
            session.close()
        except Exception as err:
            return ResponseMsg(str(err), "error")

    def apply_privileges(self, op, selfish):
        if op == "create":
            op = "create_other"
        elif selfish:
            op = op + "_self"
        else:
            op = op + "_other"
        return self.user_privileges[op]

    def prepare_game(self):
        ret_msg = self.prepare_db()
        if not ret_msg:
            return
        if ret_msg.is_error():
            self.show_messagebox(self.main_win, ret_msg)
            exit()
        elif ret_msg.is_warning():
            self.admin_needed = True

    @staticmethod
    def prepare_db():
        login = ADMIN_USER
        try:
            session = Game.get_db_session()
            insp = inspect(Game.engine)
            if not (insp.has_table(USERS_TABLE)
                    and insp.has_table(PRIV_TABLE)):
                # if not (Game.engine.has_table(USERS_TABLE)
                #         and Game.engine.has_table(PRIV_TABLE)):
                Base.metadata.create_all(Game.engine)
            r0 = session.query(BnCUsers).filter_by(login=login).first()
            session.close()
        except DatabaseError as err:
            session.rollback()
            return ResponseMsg(str(err), "error")
        except Exception as err:
            session.rollback()
            return ResponseMsg(str(err), "error")
        if not r0:
            return ResponseMsg("Please create admin user", "warning")

class AdditionalWindowMethods():
    def open_users_window(self):
        users_window = UsersWindow(self)
        #self.current_window = self.users_window
        users_window.title("Manage user profiles")
        users_window.geometry(str(UsersWindow.width) + 'x' + str(UsersWindow.height))
        users_window.resizable(0, 0)
        users_window.login_lb = Label(users_window, text='Login:', font='arial 8')
        users_window.login_lb.place(x=10, y=36)
        users_window.login_en = Entry(users_window, width=20, font='Arial 8', state='normal')
        users_window.login_en.place(x=68, y=36)
        users_window.pass_lb1 = Label(users_window, text='Password:', font='arial 8')
        users_window.pass_lb1.place(x=10, y=57)
        users_window.password_en1 = Entry(users_window, width=20, show="*", font='Arial 8', state='normal')
        users_window.password_en1.place(x=68, y=57)
        users_window.password_lb2 = Label(users_window, text='Password:', font='arial 8')
        users_window.password_lb2.place(x=10, y=78)
        users_window.password_en2 = Entry(users_window, width=20, show="*", font='Arial 8', state='normal')
        users_window.password_en2.place(x=68, y=78)
        users_window.firstname_lb = Label(users_window, text='First name:', font='arial 8')
        users_window.firstname_lb.place(x=200 + 40, y=36)
        users_window.firstname_en = Entry(users_window, width=20, font='Arial 8', state='normal')
        users_window.firstname_en.place(x=260 + 40, y=36)
        users_window.lastname_lb = Label(users_window, text='Last name:', font='arial 8')
        users_window.lastname_lb.place(x=200 + 40, y=57)
        users_window.lastname_en = Entry(users_window, width=20, font='Arial 8', state='normal')
        users_window.lastname_en.place(x=260 + 40, y=57)
        users_window.email_lb = Label(users_window, text='E-mail:', font='arial 8')
        users_window.email_lb.place(x=200 + 40, y=78)
        users_window.email_en = Entry(users_window, width=20, font='Arial 8', state='normal')
        users_window.email_en.place(x=260 + 40, y=78)
        users_window.create_bt = Button(users_window, text='Create', font='arial 10',
                                             command=users_window.create_user_eh)
        users_window.create_bt.place(x=90, y=135)
        users_window.modify_bt = Button(users_window, text='Modify', font='arial 10',
                                             command=users_window.modify_user_eh)
        users_window.modify_bt.place(x=190, y=135)
        users_window.delete_bt = Button(users_window, text='Delete', font='arial 10',
                                             command=users_window.delete_user_eh)
        users_window.delete_bt.place(x=280, y=135)
        users_window.show_pass_bt = Button(users_window, text='O_O', font='arial 6',
                                                command=users_window.show_password)
        users_window.show_pass_bt.place(x=195, y=60)
        if isinstance(self, LoginWindow):
            users_window.delete_bt["state"] = "disabled"
            users_window.modify_bt["state"] = "disabled"
        else:
            users_window.load_logged_user_info()
        users_window.transient(self)
        users_window.grab_set()
        users_window.focus_set()
        users_window.protocol('WM_DELETE_WINDOW', users_window.close)


class LoginWindow(tkinter.Toplevel, AdditionalWindowMethods):
    width = 360
    height = 180
    def __init__(self, parent_window):
        super().__init__(parent_window)
        # self.login_window_width = 360
        # self.login_window_height = 180

    def authenticate_user_eh(self):
        login = self.login_entry.get()
        password = self.password_entry.get()
        r_msg = Game.authenticate_user(login, password)
        if r_msg:
            MessageBox.show_message(self, r_msg)
            return
        self.game.loggedin_user = login
        r_msg = Game.retrieve_user_privileges(Game,login)
        if r_msg:
            MessageBox.show_message(self, r_msg)
            return
        r_msg = "You've successfully logged in!"
        if self.game.admin_needed:
            r_msg += " Please do not forget to create Administrator user."
        MessageBox.show_message(self, ResponseMsg(r_msg, "info"))
        self.grab_release()
        self.withdraw()
        self.main_win.wm_attributes('-topmost', 'yes')
        self.main_win.grab_set()
        self.main_win.focus_set()


    def change_password_eh(self):
        """

        :rtype: object
        """
        login = self.login_window_lg_en.get().strip().lower()
        password1 = self.password_en1.get().strip()
        password2 = self.password_en2.get().strip()
        r_msg = Game.validate_password(password1, password2)
        if r_msg:
            self.show_messagebox(self.restore_window, ResponseMsg(r_msg, "error"))
            return
        r_msg = self.modify_user(login, password1, only_password=True)
        if r_msg:
            self.show_messagebox(self.restore_window, r_msg)
            return
        self.show_messagebox(self.login_window, ResponseMsg("Password successfully changed", "info"))
        self.close()

    def open_restore_password_window(self):
        login = self.login_window_lg_en.get().strip().lower()
        r_msg = Game.validate_user(login, op="other")
        if r_msg:
            self.show_messagebox(self.login_window, r_msg)
            return
        user_data = self.get_user_by_login(login)
        email = user_data.email
        # self.login_window.wm_attributes('-topmost', 'no')
        self.login_window.grab_release()
        self.restore_window = tkinter.Toplevel(self.login_window)
        self.current_window = self.restore_window
        self.restore_window.title("Restore password")
        self.restore_window.geometry(str(self.restore_window_width) + 'x' + str(self.restore_window_height))
        self.restore_window.resizable(0, 0)
        # self.restore_window_lb0 = Label(self.restore_window, text='Please click button to send a pin-code to your
        # email',font='arial 9')
        self.restore_window_lb0 = Label(self.restore_window, text='Please enter a pincode sent to your email:',
                                        font='arial 9')
        self.restore_window_lb0.place(x=10, y=10)
        self.restore_window_pc_en = Entry(self.restore_window, width=6, font='Arial 9', state='normal')
        self.restore_window_pc_en.place(x=250, y=10)
        self.restore_window_pc_bt = Button(self.restore_window, text='Ok', font='arial 7',
                                           command=self.verify_pincode_eh)
        self.restore_window_pc_bt.place(x=300, y=10)
        self.restore_window_cp_lb = Label(self.restore_window, text='Please enter a new password:',
                                          font='arial 9')
        self.restore_window_cp_lb.place(x=90, y=50)
        self.restore_window_cp_lb["state"] = "disabled"
        self.password_en1 = Entry(self.restore_window, width=25, font='Arial 8', show="*", state='normal')
        self.password_en1.place(x=95, y=70)
        self.password_en1["state"] = "disabled"
        self.password_en2 = Entry(self.restore_window, width=25, font='Arial 8', show="*", state='normal')
        self.password_en2.place(x=95, y=95)
        self.password_en2["state"] = "disabled"
        self.restore_window_cp_bt = Button(self.restore_window, text='Change password', font='arial 8',
                                           command=self.change_password_eh)
        self.restore_window_cp_bt.place(x=110, y=125)
        self.restore_window_cp_bt["state"] = "disabled"
        self.restore_window_show_pass_bt = Button(self.restore_window, text='O_O', font='arial 6',
                                                  command=self.show_password)
        self.restore_window_show_pass_bt.place(x=267, y=55)
        self.restore_window_show_pass_bt["state"] = "disabled"
        # self.restore_window_bt0 = Button(self.restore_window, text='Send code', font='arial 6',
        #                                  command=self.send_pincode_eh)
        # self.restore_window_bt0.place(x=350, y=10)
        self.restore_window.transient(self.login_window)
        self.restore_window.grab_set()
        self.restore_window.focus_set()
        self.restore_window.protocol("WM_DELETE_WINDOW", self.close)
        self.send_pincode(email)


class UsersWindow(Toplevel):
    width = 440
    height = 180
    def __init__(self, parent_window):
        super().__init__(parent_window)
        self.parent_window = parent_window

    def close(self):
        self.grab_release()
        self.destroy()
        self.parent_window.grab_set()
        self.parent_window.focus_set()

    def load_logged_user_info(self):
        try:
            session = Game.get_db_session()
            r = session.query(BnCUsers).filter_by(login=self.loggedin_user).first()
            session.close()
        except Exception as err:
            session.rollback()
            return ResponseMsg(str(err), "error")
        match = re.search(r"firstname=\'(.*)\', lastname=\'(.*)\', email=\'(.*?)\'", str(r))
        login = self.loggedin_user
        firstname = match.group(1)
        lastname = match.group(2)
        email = match.group(3)
        self.login_en.insert(0, login)
        self.firstname_en.insert(0, firstname)
        self.lastname_en.insert(0, lastname)
        self.email_en.insert(0, email)

    def show_password(self):
        if self.password_en1["show"] == "*":
            self.password_en1["show"] = ""
            self.password_en2["show"] = ""
        else:
            self.password_en1["show"] = "*"
            self.password_en2["show"] = "*"

    def create_user_eh(self):
        login = self.login_en.get()
        password1 = self.password_en1.get()
        password2 = self.password_en2.get()
        firstname = self.firstname_en.get()
        lastname = self.astname_en.get()
        email = self.email_en.get()
        if self.loggedin_user and not self.apply_privileges("create", False):
            self.show_messagebox(self.users_window, ResponseMsg("You have no right to create a user", "error"))
            return
        r_msg = self.validate_user(login, password1, password2, firstname, lastname, email, op="create")
        if r_msg:
            self.show_messagebox(self.users_window, r_msg)
            return
        r_msg = self.add_user(login, password1, firstname, lastname, email)
        if r_msg:
            self.show_messagebox(self.users_window, r_msg)
            return
        self.users_window_login_en.delete(0, 'end')
        self.password_en1.delete(0, 'end')
        self.password_en2.delete(0, 'end')
        self.users_window_firstname_en.delete(0, 'end')
        self.users_window_lastname_en.delete(0, 'end')
        self.users_window_email_en.delete(0, 'end')
        r_msg = self.create_user_privileges(login)
        if r_msg:
            self.show_messagebox(self.users_window, r_msg)
            return
        self.show_messagebox(self.users_window, ResponseMsg("User successfully created", "info"))

    def delete_user_eh(self):
        login = self.users_window_login_en.get()
        login = login.strip().lower()
        if self.loggedin_user and not self.apply_privileges("delete", login == self.loggedin_user):
            self.show_messagebox(self.users_window, ResponseMsg("You have no right to delete the user", "error"))
            return
        r_msg = self.validate_user(login, op="other")
        if r_msg:
            self.show_messagebox(self.users_window, r_msg)
            return
        r_msg = self.delete_user(login)
        if r_msg:
            self.show_messagebox(self.users_window, r_msg)
            return
        self.users_window_login_en.delete(0, 'end')
        self.password_en1.delete(0, 'end')
        self.password_en2.delete(0, 'end')
        self.users_window_firstname_en.delete(0, 'end')
        self.users_window_lastname_en.delete(0, 'end')
        self.users_window_email_en.delete(0, 'end')
        r_msg = self.delete_user_privileges(login)
        if r_msg:
            self.show_messagebox(self.users_window, r_msg)
        self.show_messagebox(self.users_window, ResponseMsg("User successfully deleted", "info"))

    def modify_user_eh(self):
        login = self.users_window_login_en.get()
        login = login.strip().lower()
        password1 = self.password_en1.get()
        password2 = self.password_en2.get()
        firstname = self.users_window_firstname_en.get()
        lastname = self.users_window_lastname_en.get()
        email = self.users_window_email_en.get()
        if self.loggedin_user and not self.apply_privileges("modify", login == self.loggedin_user):
            self.show_messagebox(self.users_window, ResponseMsg("You have no right to modify the user", "error"))
            return
        r_msg = self.validate_user(login, password1, password2, firstname, lastname, email, op="modify")
        if r_msg:
            self.show_messagebox(self.users_window, r_msg)
            return
        r_msg = self.modify_user(login, password1, firstname, lastname, email, only_password=False)
        if r_msg:
            self.show_messagebox(self.users_window, r_msg)
            return
        self.users_window_login_en.delete(0, 'end')
        self.password_en1.delete(0, 'end')
        self.password_en2.delete(0, 'end')
        self.users_window_firstname_en.delete(0, 'end')
        self.users_window_lastname_en.delete(0, 'end')
        self.users_window_email_en.delete(0, 'end')
        self.show_messagebox(self.users_window, ResponseMsg("User successfully modified", "info"))


class MainWin(Tk, AdditionalWindowMethods):
    def __init__(self):
        super().__init__()
        self.initial_main_height = 200
        self.initial_main_width = 470
        self.max_messagebox_width = self.initial_main_width
        self.max_messagebox_height = self.initial_main_height
        self.button = None
        self.lb0 = None
        self.lb4 = None
        self.lb3_ = None
        self.text1 = None
        self.text2 = None

    def button_clicked(self):
        game = self.game
        if game.new_game_requested:
            game.new_game_requested = False
            self.new_game()
            self.button['text'] = "OK! Go on!"
            self.lb0['text'] = "Think of a number with " + str(game.capacity) + " unique digits!"
            self.lb0['font'] = 'arial 12'
            self.lb0['fg'] = '#0d0'
            self.lb4['text'] = "Attempts: " + str(game.attempts)
            return
        self.lb3_['text'] = "Previous set: " + str(len(game.previous_all_set))
        self.lb4['text'] = 'Attempts: ' + str(game.attempts)
        self.text1['state'] = 'normal'
        self.text2['state'] = 'normal'
        game.game_started = True
        game.new_guess()

    def verify_pincode_eh(self):
        entered_pincode = self.restore_window_pc_en.get()
        entered_pincode = entered_pincode.strip()
        r_msg = Game.validate_pincode(entered_pincode, str(self.pincode))
        if r_msg:
            self.show_messagebox(self.restore_window, r_msg)
            return
        self.restore_window_cp_lb["state"] = "normal"
        self.password_en1["state"] = "normal"
        self.password_en2["state"] = "normal"
        self.restore_window_cp_bt["state"] = "normal"
        self.restore_window_show_pass_bt["state"] = "normal"

    def mouse_function_hide(self, event):
        self.lb3_.pack_forget()

    def mouse_function_show(self, event):
        self.lb3_.pack(fill='none', side='bottom')

    def close(self):
        self.destroy()
        self.quit()

    def new_game_clicked(self):
        if not self.game_started: return
        self.new_game()
        self.button['text'] = "OK! Go on!"
        self.lb0['text'] = "Think of a number with " + str(self.capacity) + " unique digits!"
        self.lb0['font'] = 'arial 12'
        self.lb0['fg'] = '#0d0'
        self.lb4['text'] = "Attempts: " + str(self.attempts)

    def new_game(self):
        self.reset_to_initials()
        self.attempts = 0
        self.lb3_['text'] = "Previous set: 0"
        for proposed_strings_lb in self.proposed_strings_lb_list:
            proposed_strings_lb.destroy()
        self.proposed_strings_lb_list.clear()
        self.proposed_strings_list.clear()
        self.fr0.pack_forget()
        self.geometry(f'{self.initial_main_width}x{self.initial_main_height}')



    def open_login_window(self):
        login_window = LoginWindow(self)
        login_window_width = login_window.width
        login_window_height = login_window.height
        login_window.main_win = self
        login_window.game = self.game
        login_window.geometry(str(login_window_width) + 'x' + str(login_window_height))
        login_window.resizable(0, 0)
        # self.login_window.wm_attributes('-topmost', 'yes')
        login_window.label0 = Label(login_window, text='Please enter your login and password: ',
                                    font='TimesNewRoman 12', fg='#e0e')
        login_window.label0.place(x=40, y=10)
        login_window.login_lb = Label(login_window, text='Login:', font='Arial 10')
        login_window.login_lb.place(x=10, y=40)
        login_window.login_entry = Entry(login_window, width=25, font='Arial 10', state='normal')
        login_window.login_entry.place(x=100, y=40)
        login_window.password_lb = Label(login_window, text='Password:', font='arial 10')
        login_window.password_lb.place(x=10, y=80)
        login_window.password_entry = Entry(login_window, width=25, font='Arial 10', show='*', state='normal')
        login_window.password_entry.place(x=100, y=80)
        login_window.login_button = Button(login_window, text='Login', font='arial 10',
                                           command=login_window.authenticate_user_eh)
        login_window.login_button.place(x=30, y=120)
        login_window.new_user_button = Button(login_window, text='New user...', font='arial 10',
                                              command=login_window.open_users_window)
        login_window.new_user_button.place(x=90, y=120)
        login_window.recovery_button = Button(login_window, text='Reset password...', font='arial 6',
                                              command=login_window.open_restore_password_window)
        login_window.recovery_button.place(x=188, y=126)
        login_window.exit_button = Button(login_window, text='Exit', font='arial 10',
                                          command=self.close)
        login_window.exit_button.place(x=285, y=120)
        login_window.transient(self)
        login_window.grab_set()
        login_window.focus_set()
        login_window.protocol("WM_DELETE_WINDOW", self.close)





    @staticmethod
    def disable_event():
        pass

    def donothing(self):
        pass



    def finish_game(self, set_size, label_text, label_color):
        self.reset_to_initials()
        self.lb3_['text'] = "Previous set: " + str(set_size)
        self.lb0['text'] = label_text
        self.lb0['fg'] = label_color
        self.button['text'] = 'Play again!'
        self.new_game_requested = True
        self.add_item_to_history_frame()

    def change_proposed_str_on_window(self):
        self.lb0['text'] = 'I guess your number is : "' + self.game.proposed_str + '" Enter your answer:'
        self.lb0['fg'] = '#000'
        self.button['text'] = 'OK'
        self.lb4['text'] = 'Attempts: ' + str(self.game.attempts)
        if self.game.attempts > 1:
            self.add_item_to_history_frame()

    def add_item_to_history_frame(self):
        game = self.game
        h = self.initial_main_height + self.string_interval_history_frame * (len(game.proposed_strings_list) - 1)
        self.fr0.pack(expand='yes')
        self.geometry(f'{self.initial_main_width}x{h}')

        t0 = game.proposed_strings_list[-1]
        fr0_lb = Label(self.fr0, text=str(t0[0]) + "  " + str(t0[1]) + "." + str(t0[2]), font='arial 9')
        fr0_lb.pack()
        self.proposed_strings_lb_list.append(fr0_lb)

    def open_about_window(self):
        about_window = AboutWindow(self)
        about_window.game = self.game
        about_window.geometry('280x90')
        about_window.resizable(0, 0)
        about_window.lb1 = Label(
            about_window, text='This game is created by Eugene Dolgov. \nAll rights reserved \u00a9 2021.',
            font='arial 10')
        about_window.lb1.place(x=10, y=10)
        about_window.button = Button(about_window, text='OK', command=lambda: about_window.destroy())
        button.place(x=120, y=50)
        about_window.lb1.bind("<Double-Button-3>", about_window.input_your_string)
        about_window.transient(self)
        about_window.grab_set()
        about_window.focus_set()
        about_window.wait_window()



    def get_capacity(self):
        if not (self.setting_window_cap_en.get()).isdigit():
            return
        if self.capacity < 3 or self.capacity > 6:
            return
        self.capacity = int(self.setting_window_cap_en.get())
        if str(self.lb0['text']).find('Think of a number with') != 1:
            self.lb0['text'] = "Think of a number with " + str(self.capacity) + " unique digits!"
            self.lb0['fg'] = '#0d0'
        self.setting_window_cap_bt['state'] = 'disabled'
        # self.setting_window.grab_release()
        # self.setting_window.withdraw()

    def reset_to_initials(self):
        self.text1['state'] = 'disabled'
        self.text2['state'] = 'disabled'
        self.totqty_resp = None
        self.rightplace_resp = None
        self.your_string = None
        self.game_started = False
        self.available_digits_str = '0123456789'
        self.proposed_str = ''
        self.previous_all_set.clear()

    def open_setting_window(self):
        if self.text1['state'] != 'disabled' or self.text2['state'] != 'disabled':
            return

        def callback(sv):
            self.setting_window_cap_bt['state'] = 'normal'

        self.setting_window = tkinter.Toplevel(self.main_win)
        self.setting_window.title("Settings")
        self.setting_window.geometry('240x160')
        self.setting_window.resizable(0, 0)
        # self.setting_window_lf0 = LabelFrame(self.setting_window, text='Capacity:', labelanchor='n', font='arial 8', padx=30, pady=4)
        # self.setting_window_lf0.place(x=10, y=5)
        self.setting_window_cap_lb = Label(self.setting_window, text='Capacity:', font='arial 8')
        self.setting_window_cap_lb.place(x=10, y=10)
        self.setting_window_cap_bt = Button(self.setting_window, text='Apply', font='arial 7',
                                            command=game.get_capacity)
        self.setting_window_cap_bt.place(x=90, y=10)
        self.setting_window_cap_bt['state'] = 'disabled'
        sv = StringVar()
        sv.trace("w", lambda name, index, mode, sv=sv: callback(sv))
        self.setting_window_cap_en = Entry(self.setting_window, width=3, font='Arial 8', state='normal',
                                           textvariable=sv)
        self.setting_window_cap_en.place(x=65, y=10)
        self.setting_window_cap_en.delete('0', 'end')
        self.setting_window_cap_en.insert('0', self.capacity)
        self.setting_window.transient(self.main_win)
        self.setting_window.grab_set()
        self.setting_window.focus_set()
        # self.window.wait_window()

class AboutWindow(Toplevel):
    def __init__(self, parent_window):
        super().__init__(parent_window)
        self.your_string_entry = None

    def input_your_string(self, event):
        game = self.game
        if game.game_started or game.new_game_requested: return
        if not self.your_string_entry:
            self.geometry('280x110')
            self.your_string_entry = Entry(self, width=6, font='Arial 8', state='normal')
            self.your_string_entry.place(x=112, y=81)
            return
        game.your_string = self.your_string_entry.get()
        if not self.validate_your_string(game.your_string):
            game.your_string = None
            return
        self.your_string_entry.delete(0, 'end')
        self.your_string_entry.destroy()
        self.your_string_entry = None
        self.geometry('280x90')
        self.automate_answer()

    def validate_your_string(self, input_string):
        if not input_string.isdigit() or len(input_string) != self.game.capacity or len(set(list(input_string))) != len(
                list(input_string)):
            return False
        else:
            return True

    def automate_answer(self):
        game = self.game
        while not (game.totqty_resp == game.capacity and game.rightplace_resp == game.capacity):
            self.button_clicked() #continue fromm this point
            self.calc_bulls_and_cows()
        self.button_clicked()

class MessageBox(Tk):
    max_messagebox_width = 470
    max_messagebox_height = 200

    def __init__(self, parent_window):
        super().__init__()
        self.parent_window = parent_window

    @staticmethod
    def show_message(parent_window, msg):
        def myclose():
            parent_window.grab_set()
            messagebox.destroy()
        # parent_window.grab_release()
        text = str(msg.get_text())
        msg_len = len(text)
        text = text.split("\n")[0]
        text_list = text.split(" ")
        text_split_len = len(text_list)
        result_str = ''
        new_line_num = 1
        for c in text_list:
            if len(result_str) < 40 * new_line_num:
                result_str += " " + c
            else:
                new_line_num += 1
                result_str += "\n" + c
        max_messagebox_width = MessageBox.max_messagebox_width - (50 // len(sorted(text_list, key=lambda c: len(c),
                                                                        reverse=True)[0])) * 10
        max_messagebox_height = new_line_num * 20 + 20
        messagebox = tkinter.Toplevel(parent_window)
        messagebox.title(msg.get_type())
        messagebox.geometry(str(max_messagebox_width) + 'x' + str(max_messagebox_height))
        messagebox.resizable(0, 0)
        # messagebox.wm_attributes('-topmost', 'yes')
        msgbox_lb = Label(messagebox, text=result_str, font='arial 10', anchor='w')
        msgbox_lb.pack(fill='none')
        msgbox_bt = Button(messagebox, text="OK", width=12, command=lambda: myclose())
        msgbox_bt.pack(fill='none')
        messagebox.transient(parent_window)
        messagebox.grab_set()
        messagebox.focus_set()



class ResponseMsg:
    def __init__(self, msg_text, msg_type):
        self.msg_text = msg_text
        self.msg_type = msg_type

    def get_text(self):
        return self.msg_text

    def get_type(self):
        return self.msg_type.upper()

    def is_error(self):
        if self.msg_type.lower() == "error":
            return True
        else:
            return False

    def is_warning(self):
        if self.msg_type.lower() == "warning":
            return True
        else:
            return False

    def is_ok(self):
        if self.msg_type.lower() == "info":
            return True
        else:
            return False




if __name__ == '__main__':
    game = Game()
    main_win = MainWin()
    main_win.game = game
    main_win.title("Bulls and Cows Game")
    main_win.geometry(f'{main_win.initial_main_width}x{main_win.initial_main_height}')
    main_win.resizable(0, 0)
    game.prepare_game()
    main_win.menubar = Menu(main_win)
    main_win.filemenu = Menu(main_win.menubar, tearoff=0)
    main_win.filemenu.add_command(label="New", command=main_win.new_game_clicked)
    main_win.filemenu.add_command(label="Settings", command=main_win.open_setting_window)
    main_win.filemenu.add_command(label="Users", command=main_win.open_users_window)
    main_win.filemenu.add_separator()
    main_win.filemenu.add_command(label="Logout", command=main_win.donothing)
    main_win.filemenu.add_command(label="Exit", command=main_win.close)
    main_win.menubar.add_cascade(label="File", menu=main_win.filemenu)
    main_win.helpmenu = Menu(main_win.menubar, tearoff=0)
    main_win.helpmenu.add_command(label="About...", command=main_win.open_about_window)
    main_win.menubar.add_cascade(label="Help", menu=main_win.helpmenu)
    main_win.config(menu=main_win.menubar)
    main_win.lb0 = Label(main_win, text="Think of a number with " + str(game.capacity) + " unique digits!",
                         font='arial 12')
    main_win.lb0.bind("<Double-Button-1>", main_win.mouse_function_hide)
    main_win.lb0.bind("<Double-Button-3>", main_win.mouse_function_show)
    main_win.lb0['fg'] = '#0d0'
    main_win.lb0.pack(fill='none')
    main_win.lb1 = Label(main_win, text='Enter a total number of matching digits ("cows"): ', font='arial 8')
    main_win.lb1.pack(fill='none')
    main_win.text1 = Entry(main_win, width=3, font='Arial 8', state='disabled')
    main_win.text1.pack()
    main_win.lb2 = Label(main_win, text='Enter a number of digits on the right positions ("bulls"): ', font='arial 8')
    main_win.lb2.pack(fill='none')
    main_win.text2 = Entry(main_win, width=3, font='Arial 8', state='disabled')
    main_win.text2.pack()
    main_win.button = Button(main_win, text="OK! Go on!", width=20, command=main_win.button_clicked)
    main_win.button.pack(fill='none')
    main_win.lb3_ = Label(main_win, text="Previous set: " + str(len(game.previous_all_set)), font='arial 5')
    #  lb3_.pack(fill='none', side='bottom')
    #  lb3_.pack_forget()
    main_win.fr0 = LabelFrame(main_win, text='History of attempts', labelanchor='n', font='arial 8', padx='80')
    main_win.lb4 = Label(main_win, text="Attempts: " + str(game.attempts), font='arial 8')
    main_win.lb4.pack(fill='none', side='bottom')
    main_win.protocol('WM_DELETE_WINDOW', main_win.close)
    main_win.open_login_window()
    main_win.mainloop()
