import base64
import math
import hashlib
import random
import re
from collections import defaultdict
from itertools import permutations
from secrets import choice
from datetime import datetime
from time import time
from tkinter import Label, Button, Entry, Frame, PhotoImage, LabelFrame, Menu, Checkbutton
from tkinter import SUNKEN, BOTTOM, E, W, N, S, X, Y
from tkinter import Toplevel, ttk, Tk
from tkinter import StringVar, BooleanVar
import smtplib
import ssl
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

from passlib.context import CryptContext
import yaml
from yaml.loader import SafeLoader
from sqlalchemy import Column, ForeignKey, Integer, String, Boolean, TIMESTAMP
from sqlalchemy import create_engine, inspect
from sqlalchemy.orm import sessionmaker
from sqlalchemy.exc import NoSuchTableError, SQLAlchemyError, DatabaseError
from sqlalchemy.orm.session import close_all_sessions
from sqlalchemy.ext.declarative import declarative_base

CONFIG_PATH = "bnc_config.yml"
# DB_CONN_STRING = "postgresql+psycopg2://bncuser@127.0.0.1:5432/bnc"
DB_NAME = "bnc"
# USERS_TABLE = "users"
USERS_TABLE = "auth_user"
PRIV_TABLE = "privileges"
FL_TABLE = "fixture_list"
DB_COMMON_ROLE = "bnc_user"
DB_ADMIN_ROLE = "bnc_admin"

Base = declarative_base()


class BnCUsers(Base):
    __tablename__ = USERS_TABLE
    id = Column(Integer, primary_key=True, nullable=False)
    password = Column(String(128), nullable=False)
    last_login = Column(TIMESTAMP(timezone=True), nullable=True)
    is_superuser = Column(Boolean, nullable=False)
    username = Column(String(150), unique=True, nullable=False)
    first_name = Column(String(150), nullable=False)
    last_name = Column(String(150), nullable=False)
    email = Column(String(254), unique=True, nullable=False)
    is_staff = Column(Boolean, nullable=False)
    is_active = Column(Boolean, nullable=False)
    date_joined = Column(TIMESTAMP(timezone=True), nullable=False)


class Privileges(Base):
    __tablename__ = PRIV_TABLE
    id = Column(Integer, primary_key=True, nullable=False)
    # login = Column(String, ForeignKey(USERS_TABLE + ".login", ondelete="cascade"), nullable=False)
    login = Column(String, ForeignKey(USERS_TABLE + ".username", ondelete="cascade"), nullable=False)
    create_other = Column(Boolean, nullable=False)
    modify_self = Column(Boolean, nullable=False)
    modify_other = Column(Boolean, nullable=False)
    delete_self = Column(Boolean, nullable=False)
    delete_other = Column(Boolean, nullable=False)


class FixtureList(Base):
    __tablename__ = FL_TABLE
    id = Column(Integer, primary_key=True, nullable=False)
    # login = Column(String, ForeignKey(USERS_TABLE + ".login", ondelete="cascade"), nullable=False)
    login = Column(String, ForeignKey(USERS_TABLE + ".username", ondelete="cascade"), nullable=False)
    winner = Column(Integer, nullable=False)
    attempts = Column(Integer, nullable=False)
    timestamp = Column(Integer, nullable=False)
    duration = Column(Integer, nullable=False)


class Game:
    db_common_role = DB_COMMON_ROLE
    db_admin_role = DB_ADMIN_ROLE
    db_name = DB_NAME
    sessions = defaultdict(bool)

    def __init__(self, capacity=4):
        super().__init__()
        self.capacity = capacity
        self.my_history_list = list()
        self.your_history_list = list()
        self.total_set = set()
        self.current_set = set()
        self.new_game_requested = False
        self.loggedin_user = None
        self.dual_game_enabled = True
        self.user_privileges = None
        self.prepare_game()
        self.game_initials()

    @staticmethod
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

    @staticmethod
    def overlap_sets(set0, set1, iteration):
        total = set()
        while iteration > 0:
            total.clear()
            sss = (Game.overlap_set_items(a, b) for a in set0 for b in set1)
            total = set(sss)
            total.discard(None)
            # total = set(filter(lambda s: s is not None, sss))
            set1 = total.copy()
            iteration -= 1
        return total

    def get_templates(self):
        cows = self.my_cows
        bulls = self.my_bulls
        current_guess = self.guess_proposal
        capacity = self.capacity
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
                total = Game.overlap_sets(one_cow_set, one_cow_set, cows - bulls - 1)
            if bulls > 0:
                bulls_permut = set(map(tuple, map(sorted, permutations(range(len(current_guess)), bulls))))
                for i0 in bulls_permut:
                    temp = ["V" for _ in range(capacity)]
                    for i1 in i0:
                        temp[i1] = current_guess[i1]
                    only_bulls_set.add(tuple(temp))
                total = Game.overlap_sets(only_bulls_set, total, 1)
        return total

    @staticmethod
    def load_logged_user_info(loggedin_user):
        r = Game.get_user_by_login(loggedin_user)
        # match = re.search(r"firstname=\'(.*)\', lastname=\'(.*)\', email=\'(.*?)\'", str(r))
        login = loggedin_user
        firstname = str(r.first_name)
        lastname = str(r.last_name)
        email = str(r.email)
        user_data = {"login": login, "firstname": firstname, "lastname": lastname, "email": email}
        return user_data

    @staticmethod
    def generate_pincode(cap=4):
        return str(random.randint(10 ** (cap - 1), 10 ** cap - 1))

    # @staticmethod
    # def encrypt_password(password):
    #     context = CryptContext(
    #         schemes=["pbkdf2_sha256"],
    #         default="pbkdf2_sha256",
    #         pbkdf2_sha256__default_rounds=30000
    #     )
    #     return context.hash(password)
    #
    # @staticmethod
    # def check_password(password, hashed):
    #     context = CryptContext(
    #         schemes=["pbkdf2_sha256"],
    #         default="pbkdf2_sha256",
    #         pbkdf2_sha256__default_rounds=30000
    #     )
    #     try:
    #         r = context.verify(password, hashed)
    #     except:
    #         raise
    #     if not r:
    #         raise IncorrectPasswordException

    @staticmethod
    def send_email(email, message_type, replace_list):
        password = Game.base64_decode_(Game.smtp_password)
        smtp_address = Game.smtp_address
        ssl_port = Game.ssl_port
        email_msg = MIMEMultipart("alternative")
        sender_email = Game.bnc_email
        receiver_email = email
        # receiver_email = "stayerx@gmail.com"
        subject = Game.email_messages[message_type]['subject']
        email_msg["Subject"] = subject
        email_msg["From"] = sender_email
        email_msg["To"] = receiver_email
        ### continue
        text = Game.email_messages[message_type]['text']
        html = Game.email_messages[message_type]['html']
        for e in replace_list:
            text = text.replace(e[0], e[1])
            html = html.replace(e[0], e[1])
        p1 = MIMEText(text, "plain")
        p2 = MIMEText(html, "html")
        email_msg.attach(p1)
        email_msg.attach(p2)
        context = ssl.create_default_context()
        try:
            with smtplib.SMTP_SSL(smtp_address, ssl_port, context=context) as srv:
                srv.login(sender_email, password)
                srv.sendmail(sender_email, receiver_email, email_msg.as_string())
        except Exception:
            raise

    @staticmethod
    def validate_pincode(entered_pincode, correct_pincode):
        if not entered_pincode.isnumeric():
            raise BnCException("Pin code must contain only digits")
        if correct_pincode != entered_pincode:
            raise BnCException("Incorrect pincode")

    def get_new_guess_proposal(self):
        new_guess_proposal = ''
        while len(new_guess_proposal) < self.capacity:
            c = str(random.randint(0, 9))
            if (not (c in self.guess_proposal)) and (not (c in new_guess_proposal)):
                new_guess_proposal += c
        self.guess_proposal = new_guess_proposal

    # @staticmethod
    # def populate(interim_str, items_for_templates):
    #     guess_set = set()
    #     if interim_str.count('V') == 0:
    #         guess_set.add(''.join(interim_str))
    #     else:
    #         for y in items_for_templates:
    #             i = 0
    #             a = ''
    #             for z in interim_str:
    #                 if z == "V":
    #                     a += y[i]
    #                     i += 1
    #                 else:
    #                     a += z
    #             guess_set.add(a[:])
    #     return guess_set

    def get_items_for_templates(self):
        items_for_templates = []
        capacity = self.capacity
        my_cows = self.my_cows
        init_rest_str = self.available_digits_str
        for a in self.guess_proposal:
            init_rest_str = init_rest_str.replace(a, '')
        if capacity - my_cows > 0:
            for l in permutations(init_rest_str, capacity - my_cows):
                items_for_templates.append(''.join(map(str, l)))
        return items_for_templates

    def my_guess(self):
        """
        The method figures out my next guess proposal based on number
        of cows and bulls that were given by you (user) for my current guess proposal.
        :param my_cows_raw: Number of cows entered by you
                    (an overall number of digits that I (script)
                    managed to guess from the current guess proposal)
        :param my_bulls_raw: Number of bulls entered by you
                    (a number of digits of the correct positions that I (script)
                    managed to guess from the current guess proposal)
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

        capacity = self.capacity
        my_cows = self.my_cows
        my_bulls = self.my_bulls
        self.my_history_list.append((self.guess_proposal, my_cows, my_bulls))
        if my_cows == capacity and my_bulls == capacity:
            # raise FinishedOKException
            return True
        if my_cows == 0 and my_bulls == 0:
            for a in self.guess_proposal:
                self.available_digits_str = self.available_digits_str.replace(a, '')
            if len(self.total_set) > 0:
                for c in list(self.total_set):
                    for cc in self.guess_proposal:
                        if cc in c:
                            self.total_set.remove(c)
                            break
                if len(self.total_set) == 0:
                    raise FinishedNotOKException
                self.guess_proposal = choice(tuple(self.total_set))
            else:
                self.get_new_guess_proposal()
            self.attempts += 1
            return False
        templates_set = self.get_templates()
        if my_cows == capacity:
            lst = ["".join(x) for x in templates_set]
        else:
            items_for_templates = self.get_items_for_templates()
            lst = [populate_template(a, b) for a in templates_set for b in items_for_templates]
        self.current_set = set(lst)
        if len(self.total_set) > 0:
            self.total_set = self.total_set & self.current_set
        else:
            self.total_set = self.current_set.copy()
        # self.write_set()
        if len(self.total_set) == 0:
            raise FinishedNotOKException
        self.guess_proposal = choice(tuple(self.total_set))
        self.attempts += 1
        self.current_set.clear()
        return False

    def write_set(self):
        guess_proposal = str(self.guess_proposal)
        cows = str(self.my_cows)
        bulls = str(self.my_bulls)
        path = "dump_set_" + guess_proposal + "_" + cows + "_" + bulls
        with open(path, "w") as f:
            f.write(guess_proposal + '\n')
            f.write(cows + '\n')
            f.write(bulls + '\n')
            for i in self.total_set:
                f.write(str("".join(i)) + '\n')

    @staticmethod
    def calc_bulls_and_cows(true_number: str, guess_number: str):
        """
        The method calculates a number of cows and a number of bulls based on the true number and a guess number
        :param true_number: string
        :param guess_number: string
        :return: tuple (cows, bulls)
        """
        cows = bulls = 0
        for i0, c0 in enumerate(true_number):
            for i1, c1 in enumerate(guess_number):
                if c0 == c1:
                    cows += 1
                    if i0 == i1:
                        bulls += 1
                    break
        return (cows, bulls)

    @staticmethod
    def validate_cows_and_bulls(cows_raw, bulls_raw, capacity):
        if not (cows_raw.isdigit() and bulls_raw.isdigit()):
            raise BnCException("Number of Cows and Bulls must be a digit")
        cows = int(cows_raw)
        bulls = int(bulls_raw)
        if (cows == capacity and bulls == capacity - 1) or (
                bulls > cows) or bulls > capacity or cows > capacity:
            raise BnCException("Erroneous input combination! Try again!")

    def your_guess(self, your_guess_string):
        if self.attempts < 1:
            return False
        self.your_cows, self.your_bulls = self.calc_bulls_and_cows(self.my_string_for_you, your_guess_string)
        self.your_history_list.append((your_guess_string, self.your_cows, self.your_bulls))
        if self.your_cows == self.capacity and self.your_bulls == self.capacity:
            return True
        else:
            return False

    def think_of_number_for_you(self):
        self.my_string_for_you = "".join(choice(list(permutations("0123456789", self.capacity))))

    @staticmethod
    def create_db_user(login_to_create, password_to_create):
        try:
            session = Game.get_db_session(Game.default_db_user, Game.default_db_password)
            engine = session.bind.engine
            if login_to_create != Game.admin_user:
                sql_command = f"create user {login_to_create} with " \
                              f"encrypted password '{password_to_create}' in role {Game.db_common_role}"
            else:
                sql_command = f"create user {login_to_create} with " \
                              f"encrypted password '{password_to_create}' in role {Game.db_admin_role}"
            with engine.connect() as con:
                con.execute(sql_command)
        except Exception:
            raise

    @staticmethod
    def modify_db_user(login_to_modify, password_to_modify):
        try:
            session = Game.get_db_session(Game.default_db_user, Game.default_db_password)
            engine = session.bind.engine
            sql_command = f"alter role {login_to_modify} with encrypted password '{password_to_modify}'"
            Game.sessions[login_to_modify] = None
            Game.get_db_session(login_to_modify, password_to_modify)
            with engine.connect() as con:
                con.execute(sql_command)
        except Exception:
            raise

    @staticmethod
    def delete_db_user(login_to_delete):
        try:
            session = Game.get_db_session(Game.default_db_user, Game.default_db_password)
            engine = session.bind.engine
            sql_command = f"drop role {login_to_delete}"
            with engine.connect() as con:
                con.execute(sql_command)
        except Exception:
            raise

    @staticmethod
    def validate_db_user(login, op):
        try:
            session = Game.get_db_session(Game.default_db_user, Game.default_db_password)
            engine = session.bind.engine
            sql_command = f"select * from pg_roles where rolname='{login}'"
            with engine.connect() as con:
                result = con.execute(sql_command)
        except Exception:
            raise
        try:
            next(result)
        except StopIteration:
            if op != "create":
                raise BnCException("No such user in the database!")
            return
        if op == "create":
            raise BnCException("The user already exists in the database! "
                               "Ask database administrator to delete him")

    @staticmethod
    def create_user(*args):
        login, password, firstname, lastname, email, db_user = args
        login = login.strip()
        password = password.strip()
        firstname = firstname.strip()
        lastname = lastname.strip()
        email = email.strip().lower()
        user = BnCUsers(
            username=login,
            first_name=firstname,
            last_name=lastname,
            email=email,
            password=encrypt_password(password)
        )
        try:
            Game.validate_db_user(db_user, "other")
            session = Game.get_db_session(db_user, "")
            session.add(user)
            session.commit()
            session.close()
        except Exception:
            try:
                session.rollback()
            except:
                pass
            raise

    @staticmethod
    def modify_user(*args, only_password):
        if only_password:
            login, password, db_user = args
            login = login.strip().lower()
            password = password.strip()
        else:
            login, password, firstname, lastname, email, db_user = args
            login = login.strip().lower()
            password = password.strip()
            firstname = firstname.strip()
            lastname = lastname.strip()
            email = email.strip().lower()
        try:
            Game.validate_db_user(db_user, "other")
            session = Game.get_db_session(db_user, "")
            if only_password:
                session.query(BnCUsers).filter_by(username=login).update({"username": login,
                                                                          "password": encrypt_password(password)})
            else:
                session.query(BnCUsers).filter_by(username=login).update({"username": login,
                                                                          "first_name": firstname,
                                                                          "last_name": lastname,
                                                                          "email": email,
                                                                          "password": encrypt_password(password)})
            session.commit()
            session.close()
        except Exception:
            try:
                session.rollback()
            except:
                pass
            raise

    @staticmethod
    def delete_user(login, db_user):
        login = login.strip().lower()
        try:
            Game.validate_db_user(db_user, "other")
            session = Game.get_db_session(db_user, "")
            # session.query(Privileges).filter_by(login=login).delete()
            session.query(BnCUsers).filter_by(
                username=login).delete()  # cascade deleting in DB (from all referenced tables)
            session.commit()
            session.close()
        except Exception as err:
            try:
                session.rollback()
            except:
                pass
            raise

    @staticmethod
    def get_user_by_login(login):
        try:
            session = Game.get_db_session(Game.default_db_user, Game.default_db_password)
            r0 = session.query(BnCUsers).filter_by(username=login).first()
            session.close()
        except Exception:
            try:
                session.rollback()
            except:
                pass
            raise
        return r0

    def retrieve_user_privileges(self, login):
        try:
            session = Game.get_db_session(self.default_db_user, self.default_db_password)
            r0 = session.query(Privileges).filter_by(login=login).first()
            session.close()
        except Exception as err:
            session.rollback()
            raise err
        self.user_privileges = {'create_other': r0.create_other, 'modify_self': r0.modify_self,
                                'modify_other': r0.modify_other, 'delete_self': r0.delete_self,
                                'delete_other': r0.delete_other}

    @staticmethod
    def create_user_privileges(login, db_user):
        if login == Game.admin_user:
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
        try:
            Game.validate_db_user(db_user, "other")
            session = Game.get_db_session(db_user, "")
            session.add(privileges)
            session.commit()
            session.close()
        except Exception as err:
            try:
                session.rollback()
            except:
                pass
            raise

    @staticmethod
    def delete_user_privileges(login, db_user):
        try:
            Game.validate_db_user(db_user, "other")
            session = Game.get_db_session(db_user, "")
            session.query(Privileges).filter_by(login=login).delete()
            session.commit()
            session.close()
        except Exception:
            raise

    def apply_privileges(self, op, selfish):
        if op == "create":
            op = "create_other"
        elif selfish:
            op = op + "_self"
        else:
            op = op + "_other"
        return self.user_privileges[op]

    @staticmethod
    def get_db_session(user, password):
        if not Game.sessions[user]:
            if user == Game.default_db_user:
                password = Game.base64_decode_(password)
            db_conn_string = Game.db_conn_string_pre + str(user) + ":" + str(password) + "@" \
                             + Game.db_socket + "/" + Game.db_name
            # m = re.search(r":([^/].+)@", DB_CONN_STRING)
            # db_conn_string = DB_CONN_STRING.replace(m.group(1), Game.base64_decode_(m.group(1)))
            try:
                if user != Game.default_db_user:
                    Game.validate_db_user(user, "other")
                engine = create_engine(db_conn_string)
                DBSession = sessionmaker(bind=engine)
                Game.sessions[user] = DBSession()
                return Game.sessions[user]
            except Exception:
                raise
        return Game.sessions[user]

    @staticmethod
    def validate_user(*args, op):
        login_pattern_0 = re.compile(r'[^\w\-]')
        login_pattern_1 = re.compile(r'^[^A-Za-z]')
        firstname_pattern = re.compile(r'[^A-Za-z_-]')
        lastname_pattern = re.compile(r'[^A-Za-z_-]')
        email_pattern = re.compile(r'[\w.+$%!?\'-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[a-z]{2,9}$')
        ret_message = ""
        if op == "other" or op == "modify":
            if op == "modify":
                login, password1, password2, firstname, lastname, email = args
            else:
                login, = args
            login = login.strip()
            login_search_0 = login_pattern_0.search(login)
            login_search_1 = login_pattern_1.search(login)
            if 4 > len(login):
                ret_message += "Login is too short. Login must consist of at least 4 symbols. "
            elif 10 < len(login):
                ret_message += "Login is too long. Maximum length of login is 10 symbols. "
            elif login_search_0:
                ret_message += "Login contains inappropriate symbols. "
            elif login_search_1:
                ret_message += "Login must begin with a letter. "
            if ret_message:
                raise BnCException(ret_message)
            r0 = Game.get_user_by_login(login)
            if not r0:
                raise InvalidLoginException(True)
            if op == "other":
                return
        login, password1, password2, firstname, lastname, email = args
        login = login.strip().lower()
        password1 = password1.strip()
        password2 = password2.strip()
        firstname = firstname.strip()
        lastname = lastname.strip()
        email = email.strip().lower()
        login_search_0 = login_pattern_0.search(login)
        login_search_1 = login_pattern_1.search(login)
        email_search = email_pattern.search(email)
        if 4 > len(login):
            ret_message += "Login is too short. Login must consist of at least 4 symbols. "
        elif 20 < len(login):
            ret_message += "Login is too long. Maximal length of login is 10 symbols. "
        elif login_search_0:
            ret_message += "Login contains inappropriate symbols. "
        elif login_search_1:
            ret_message += "Login must begin with a letter. "
        ret_message += Game.validate_password(password1, password2)
        if 1 > len(firstname):
            ret_message += "First name is too short. It must consist of 1 symbol at least. "
        elif 20 < len(firstname):
            ret_message += "First name is too long. Maximal length of first name is 20 symbols. "
        elif firstname_pattern.search(firstname):
            ret_message += "First name contains inappropriate symbols. "
        if 1 > len(lastname):
            ret_message += "Last name is too short. It must consist of 1 symbol at least. "
        elif 20 < len(lastname):
            ret_message += "Last name is too long. Maximal length of last name is 20 symbols. "
        elif lastname_pattern.search(lastname):
            ret_message += "Last name contains inappropriate symbols. "
        if not email_search:
            ret_message += "E-mail contains inappropriate symbols. "
        if ret_message:
            raise BnCException(ret_message)
        if op == "create":
            try:
                r0 = Game.get_user_by_login(login)
                session = Game.get_db_session(Game.default_db_user, Game.default_db_password)
                r1 = session.query(BnCUsers).filter_by(email=email).first()
                session.close()
            except Exception:
                try:
                    session.rollback()
                except:
                    pass
                raise
            if r0:
                ret_message += "User with this login already exists! "
            if r1:
                ret_message += "User with this e-mail already exists! "
            if ret_message:
                raise BnCException(ret_message)

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
            ret_message += "Password is too short. Minimal length of password is 6 symbols. "
        elif 15 < len(password1):
            ret_message += "Password is too long. Maximal length of password is 15 symbols"
        elif s0_p is None or s1_p is None or s2_p is None or s3_p is None:
            ret_message += "Password must contain at least one capital letter, one lowercase letter, one digit " + \
                           "and one special symbol. "
        return ret_message

    @staticmethod
    def authenticate_user(login, password_entered):
        login = login.strip().lower()
        try:
            Game.validate_user(login, op="other")
            user_data = Game.get_user_by_login(login)
            # admin_data = Game.get_user_by_login(Game.admin_user)
        except Exception:
            raise
        if not user_data:
            raise BnCException("User not found!")
        # match = re.search(r"password=\'(.*)\'", str(r0))
        password_hashed = user_data.password
        try:
            check_password(password_entered, password_hashed)
        except Exception:
            return
        return True
        # if not admin_data:
        #     raise NoAdminException

    def prepare_game(self):
        try:
            self.prepare_db()
        except Exception as exc:
            MessageBox.show_message(None, ErrorMessage(exc))
            exit()

    @staticmethod
    def prepare_db():
        try:
            session = Game.get_db_session(Game.default_db_user, Game.default_db_password)
            inspection = inspect(session.bind.engine)
            if not (inspection.has_table(USERS_TABLE)
                    and inspection.has_table(PRIV_TABLE)
                    and inspection.has_table(FL_TABLE)):
                raise BnCException("Database error. No necessary db tables.")
                # Base.metadata.create_all(session.bind.engine)
        except Exception:
            raise

    @staticmethod
    def base64_decode_(encoded_string):
        return base64.b64decode(encoded_string.encode("ascii")).decode("ascii")

    @staticmethod
    def validate_your_string(capacity, input_string):
        if not input_string.isdigit() or len(input_string) != capacity or len(set(list(input_string))) != len(
                list(input_string)):
            raise BnCException("You entered an invalid string trying to guess my number!")
        return True

    def game_initials(self):
        self.total_set.clear()
        self.current_set.clear()
        self.my_history_list.clear()
        self.your_history_list.clear()
        self.my_cows = None
        self.my_bulls = None
        self.your_string_for_automation_game = None
        self.my_string_for_you = None
        self.your_cows = None
        self.your_bulls = None
        self.available_digits_str = '0123456789'
        self.guess_proposal = ''
        self.attempts = 0
        self.game_started = False
        self.start_timestamp = None
        self.finish_timestamp = None

    def write_fl_to_db(self, result_code):

        fl_item = FixtureList(
            login=self.loggedin_user,
            winner=result_code,  # continue from this
            attempts=self.attempts,
            timestamp=self.start_timestamp,
            duration=math.ceil(self.finish_timestamp - self.start_timestamp) / 60
        )
        try:
            session = Game.get_db_session(self.loggedin_user, "")
            session.add(fl_item)
            session.commit()
            session.close()
        except Exception:
            try:
                session.rollback()
            except:
                pass
            raise

    def read_fl_from_db(self):
        try:
            session = Game.get_db_session(self.loggedin_user, "")
            data = session.query(FixtureList).all()
            session.close()
        except Exception:
            try:
                session.rollback()
            except:
                pass
            raise
        return data

    def get_data_for_fixture_table(self):
        fl_data_from_db = self.read_fl_from_db()
        data_for_treeview = list()
        for row in fl_data_from_db:
            login = str(row.login)
            user_data = self.get_user_by_login(login)
            first_name = str(user_data.firstname)
            last_name = str(user_data.lastname)
            if int(row.winner) == 1:
                winner = "Me"
            elif int(row.winner) == 2:
                winner = "You"
            else:
                winner = "Tie"
            attempts = int(row.attempts)
            date = datetime.fromtimestamp(int(row.timestamp)).strftime("%Y.%m.%d")
            duration = str(row.duration) + "min"
            entry = (login, first_name, last_name, winner, attempts, date, duration)
            data_for_treeview.append(entry)
        return data_for_treeview


class AdditionalWindowMethods:
    def open_users_window_eh(self):
        users_window = UsersWindow(self)
        # self.current_window = self.users_window
        users_window.game = self.game
        users_window.main_win = self
        users_window.title("Manage user profiles")
        users_window.geometry(str(UsersWindow.width) + 'x' + str(UsersWindow.height))
        users_window.resizable(0, 0)
        users_window.login_label = Label(users_window, text='Login:', font='arial 8')
        users_window.login_label.place(x=10, y=36)
        users_window.login_entry = Entry(users_window, width=20, font='Arial 8', state='normal')
        users_window.login_entry.place(x=68, y=36)
        users_window.password_label1 = Label(users_window, text='Password:', font='arial 8')
        users_window.password_label1.place(x=10, y=57)
        users_window.password_entry1 = Entry(users_window, width=20, show="*", font='Arial 8', state='normal')
        users_window.password_entry1.place(x=68, y=57)
        users_window.password_label2 = Label(users_window, text='Password:', font='arial 8')
        users_window.password_label2.place(x=10, y=78)
        users_window.password_entry2 = Entry(users_window, width=20, show="*", font='Arial 8', state='normal')
        users_window.password_entry2.place(x=68, y=78)
        users_window.firstname_label = Label(users_window, text='First name:', font='arial 8')
        users_window.firstname_label.place(x=200 + 40, y=36)
        users_window.firstname_entry = Entry(users_window, width=20, font='Arial 8', state='normal')
        users_window.firstname_entry.place(x=260 + 40, y=36)
        users_window.lastname_label = Label(users_window, text='Last name:', font='arial 8')
        users_window.lastname_label.place(x=200 + 40, y=57)
        users_window.lastname_entry = Entry(users_window, width=20, font='Arial 8', state='normal')
        users_window.lastname_entry.place(x=260 + 40, y=57)
        users_window.email_label = Label(users_window, text='E-mail:', font='arial 8')
        users_window.email_label.place(x=200 + 40, y=78)
        users_window.email_entry = Entry(users_window, width=20, font='Arial 8', state='normal')
        users_window.email_entry.place(x=260 + 40, y=78)
        users_window.create_button = Button(users_window, text='Create', font='arial 10',
                                            command=users_window.create_user_eh)
        users_window.create_button.place(x=90, y=135)
        users_window.modify_button = Button(users_window, text='Modify', font='arial 10',
                                            command=users_window.modify_user_eh)
        users_window.modify_button.place(x=190, y=135)
        users_window.delete_button = Button(users_window, text='Delete', font='arial 10',
                                            command=users_window.delete_user_eh)
        users_window.delete_button.place(x=280, y=135)
        users_window.show_button = Button(users_window, text='O_O', font='arial 6',
                                          command=users_window.show_password)
        users_window.show_button.place(x=195, y=60)
        if isinstance(self, LoginWindow):
            users_window.delete_button["state"] = "disabled"
            users_window.modify_button["state"] = "disabled"
        else:
            try:
                user_data = Game.load_logged_user_info(self.game.loggedin_user)
            except Exception as exc:
                MessageBox.show_message(self, ErrorMessage(exc))
                return
            users_window.login_entry.insert(0, user_data["login"])
            users_window.firstname_entry.insert(0, user_data["firstname"])
            users_window.lastname_entry.insert(0, user_data["lastname"])
            users_window.email_entry.insert(0, user_data["email"])
        users_window.transient(self)
        users_window.grab_set()
        users_window.focus_set()
        users_window.protocol('WM_DELETE_WINDOW', users_window.close)


class LoginWindow(Toplevel, AdditionalWindowMethods):
    width = 360
    height = 180

    def __init__(self, parent_window):
        super().__init__(parent_window)
        self.parent_window = parent_window
        # self.login_window_width = 360
        # self.login_window_height = 180

    def authenticate_user_eh(self):
        admin_needed = False
        login = self.login_entry.get()
        password = self.password_entry.get()
        try:
            Game.authenticate_user(login, password)
        except NoAdminException:
            admin_needed = True
        except Exception as err:
            MessageBox.show_message(self, ErrorMessage(str(err)))
            return
        try:
            self.game.retrieve_user_privileges(login)
        except Exception as err:
            MessageBox.show_message(self, ErrorMessage(str(err)))
            return
        self.game.loggedin_user = login
        Game.get_db_session(login, password)  # remember the session for the logged in user
        r_msg = "You've successfully logged in!"
        if admin_needed:
            r_msg += " Please do not forget to create Administrator user (login \"admin\")."
        MessageBox.show_message(self, InfoMessage(r_msg))

    def open_restore_password_window(self):
        login = self.login_entry.get().strip().lower()
        try:
            Game.validate_user(login, op="other")
            user_data = Game.get_user_by_login(login)
        except Exception as exc:
            MessageBox.show_message(self, ErrorMessage(exc))
            return
        email = user_data.email
        # self.login_window.wm_attributes('-topmost', 'no')
        recovery_window = RecoveryPasswordWindow(self)
        recovery_window.login = login
        recovery_window.title("Reset password")
        recovery_window.geometry(str(RecoveryPasswordWindow.width) + 'x' + str(RecoveryPasswordWindow.height))
        recovery_window.resizable(0, 0)
        recovery_window.pincode_label = Label(recovery_window, text='Please enter a pincode sent to your email:',
                                              font='arial 9')
        recovery_window.pincode_label.place(x=10, y=10)
        recovery_window.pincode_entry = Entry(recovery_window, width=6, font='Arial 9', state='normal')
        recovery_window.pincode_entry.place(x=250, y=10)
        recovery_window.pincode_button = Button(recovery_window, text='Ok', font='arial 7',
                                                command=recovery_window.verify_pincode_eh)
        recovery_window.pincode_button.place(x=300, y=10)
        recovery_window.password_label = Label(recovery_window, text='Please enter a new password:',
                                               font='arial 9')
        recovery_window.password_label.place(x=90, y=50)
        recovery_window.password_label["state"] = "disabled"
        recovery_window.password_entry1 = Entry(recovery_window, width=25, font='Arial 8', show="*", state='normal')
        recovery_window.password_entry1.place(x=95, y=70)
        recovery_window.password_entry1["state"] = "disabled"
        recovery_window.password_entry2 = Entry(recovery_window, width=25, font='Arial 8', show="*", state='normal')
        recovery_window.password_entry2.place(x=95, y=95)
        recovery_window.password_entry2["state"] = "disabled"
        recovery_window.password_button = Button(recovery_window, text='Change password', font='arial 8',
                                                 command=recovery_window.change_password_eh)
        recovery_window.password_button.place(x=70, y=125)
        recovery_window.password_button["state"] = "disabled"
        recovery_window.show_button = Button(recovery_window, text='Close', font='arial 8',
                                             command=recovery_window.close)
        recovery_window.show_button.place(x=220, y=125)
        recovery_window.show_button = Button(recovery_window, text='O_O', font='arial 6',
                                             command=recovery_window.show_password)
        recovery_window.show_button.place(x=267, y=55)
        recovery_window.show_button["state"] = "disabled"
        self.grab_release()
        recovery_window.transient(self)
        recovery_window.grab_set()
        recovery_window.focus_set()
        recovery_window.protocol("WM_DELETE_WINDOW", recovery_window.close)
        recovery_window.pincode = Game.generate_pincode()
        replace_list = (("PINCODE", recovery_window.pincode),)
        try:
            Game.send_email(email, "pincode", replace_list)
        except Exception as exc:
            MessageBox.show_message(self, ErrorMessage(exc))
        recovery_window.close()
        recovery_window.game = self.game


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

    def show_password(self):
        if self.password_entry1["show"] == "*":
            self.password_entry1["show"] = ""
            self.password_entry2["show"] = ""
        else:
            self.password_entry1["show"] = "*"
            self.password_entry2["show"] = "*"

    def create_user_eh(self):
        game = self.game
        login = self.login_entry.get().strip().lower()
        password1 = self.password_entry1.get().strip()
        password2 = self.password_entry2.get().strip()
        firstname = self.firstname_entry.get().strip()
        lastname = self.lastname_entry.get().strip()
        email = self.email_entry.get().strip()
        db_user = game.loggedin_user if game.loggedin_user else login
        if game.loggedin_user and not game.apply_privileges("create", False):
            MessageBox.show_message(self,
                                    ErrorMessage("You have no right to create a user (you are not Administrator)"))
            return
        try:

            Game.validate_user(login, password1, password2, firstname, lastname, email, op="create")
            Game.validate_db_user(login, "create")
            Game.create_db_user(login, password1)
            if not game.loggedin_user:
                Game.get_db_session(login, password1)
            Game.create_user(login, password1, firstname, lastname, email, db_user)
            Game.create_user_privileges(login, db_user)
        except Exception as exc:
            MessageBox.show_message(self, ErrorMessage(exc))
            return
        replace_list = (("FIRSTNAME", firstname), ("LASTNAME", lastname))
        try:
            Game.send_email(email, "welcome", replace_list)
        except Exception as exc:
            MessageBox.show_message(self, ErrorMessage(exc))
        self.login_entry.delete(0, 'end')
        self.password_entry1.delete(0, 'end')
        self.password_entry2.delete(0, 'end')
        self.firstname_entry.delete(0, 'end')
        self.lastname_entry.delete(0, 'end')
        self.email_entry.delete(0, 'end')
        MessageBox.show_message(self, InfoMessage("User successfully created"))

    def delete_user_eh(self):
        game = self.game
        login = self.login_entry.get()
        login = login.strip().lower()
        if game.loggedin_user and not game.apply_privileges("delete", login == game.loggedin_user):
            MessageBox.show_message(self,
                                    ErrorMessage("You have no right to delete the user (you are not Administrator)"))
            return
        try:
            Game.validate_user(login, op="other")
        except Exception as exc:
            MessageBox.show_message(self, ErrorMessage(exc))
            return
        if game.loggedin_user == login:
            self.login_for_deleting = login
            if game.game_started:
                text = "You are about to remove your account. Therefore the game will be finished " \
                       "and you will be logged out. Are you sure to proceed?"
            else:
                text = "You are about to remove your account. You will be logged out." \
                       " Are you sure to proceed?"
            msg = WarningMessage(text)
            MessageBox.show_logout_message(self, msg, True)  # continue from this
            return
        self.proceed_deleting(login)
        self.login_entry.delete(0, 'end')
        self.password_entry1.delete(0, 'end')
        self.password_entry2.delete(0, 'end')
        self.firstname_entry.delete(0, 'end')
        self.lastname_entry.delete(0, 'end')
        self.email_entry.delete(0, 'end')
        MessageBox.show_message(self, InfoMessage("User successfully deleted"))

    def modify_user_eh(self):
        game = self.game
        login = self.login_entry.get()
        login = login.strip().lower()
        password1 = self.password_entry1.get()
        password2 = self.password_entry2.get()
        firstname = self.firstname_entry.get()
        lastname = self.lastname_entry.get()
        email = self.email_entry.get()
        if game.loggedin_user and not game.apply_privileges("modify", login == game.loggedin_user):
            MessageBox.show_message(self,
                                    ErrorMessage("You have no right to modify the user (you are not Administrator)"))
            return
        try:
            Game.modify_db_user(login, password1)
            Game.validate_user(login, password1, password2, firstname, lastname, email, op="modify")
            Game.modify_user(login, password1, firstname, lastname, email, game.loggedin_user, only_password=False)
        except Exception as exc:
            MessageBox.show_message(self, ErrorMessage(exc))
            return
        self.login_entry.delete(0, 'end')
        self.password_entry1.delete(0, 'end')
        self.password_entry2.delete(0, 'end')
        self.firstname_entry.delete(0, 'end')
        self.lastname_entry.delete(0, 'end')
        self.email_entry.delete(0, 'end')
        MessageBox.show_message(self, InfoMessage("User successfully modified"))

    def proceed_deleting(self, login):
        game = self.game
        try:
            Game.delete_user(login, game.loggedin_user)
            # Game.delete_user_privileges(login, game.loggedin_user)
            Game.delete_db_user(login)
        except Exception as exc:
            MessageBox.show_message(self, ErrorMessage(exc))
            return


class RecoveryPasswordWindow(UsersWindow):
    width = 350
    height = 180

    def __init__(self, parent_window):
        super().__init__(parent_window)
        self.parent_window = parent_window
        self.pincode = None

    def change_password_eh(self):
        """

        :rtype: object
        """
        login = self.login
        password1 = self.password_entry1.get().strip()
        password2 = self.password_entry2.get().strip()

        r_msg = Game.validate_password(password1, password2)
        if r_msg:
            MessageBox.show_message(self, ErrorMessage(r_msg))
            return
        try:
            Game.modify_db_user(login, password1)
            Game.modify_user(login, password1, login, only_password=True)
        except Exception as exc:
            MessageBox.show_message(self, ErrorMessage(exc))
            return
        MessageBox.show_message(self, InfoMessage("Password successfully changed"))
        # self.close() # refactor

    def verify_pincode_eh(self):
        entered_pincode = self.pincode_entry.get().strip()
        try:
            Game.validate_pincode(entered_pincode, str(self.pincode))
        except Exception as exc:
            MessageBox.show_message(self, ErrorMessage(exc))
            return
        self.password_label["state"] = "normal"
        self.password_entry1["state"] = "normal"
        self.password_entry2["state"] = "normal"
        self.password_button["state"] = "normal"
        self.show_button["state"] = "normal"
        self.pincode_label["state"] = "disabled"
        self.pincode_entry["state"] = "disabled"
        self.pincode_button["state"] = "disabled"


class MainWin(Tk, AdditionalWindowMethods):
    upper_label_normal_color = "#a11"

    def __init__(self):
        super().__init__()
        self.mono_game_main_height = 200
        self.mono_game_main_width = 400
        self.dual_game_main_height = self.mono_game_main_height + 100
        self.dual_game_main_width = int(1.4 * self.mono_game_main_width)
        self.string_interval_history_frame = 22
        self.info_pic = PhotoImage(file="info_pic.gif")
        self.error_pic = PhotoImage(file="error_pic.gif")
        self.warning_pic = PhotoImage(file="warning_pic.gif")
        LabelPics.info_pic = self.info_pic
        LabelPics.error_pic = self.error_pic
        LabelPics.warning_pic = self.warning_pic
        self.windows_initials()

    def windows_initials(self):
        self.go_button = None
        self.upper_label = None
        self.attempts_label = None
        self.status_label = None
        self.lb3_ = None
        self.my_cows_label = None
        self.my_cows_entry = None
        self.my_bulls_label = None
        self.my_bulls_entry = None
        self.my_history_frame = None
        self.my_outer_frame = None
        self.your_guess_entry = None
        self.your_cows_label = None
        self.your_bulls_label = None
        self.your_history_frame = None
        self.your_outer_frame = None
        self.my_history_lb_list = list()
        self.your_history_lb_list = list()
        self.count = 0

    def show_main_window_menu(self):
        self.menubar = Menu(self)
        self.filemenu = Menu(self.menubar, tearoff=0)
        self.filemenu.add_command(label="New", command=self.new_game_clicked_eh)
        self.filemenu.add_command(label="Settings", command=self.open_setting_window_eh)
        self.filemenu.add_command(label="Users", command=self.open_users_window_eh)
        self.filemenu.add_command(label="Fixture List", command=self.open_fixture_list_window_eh)
        self.filemenu.add_separator()
        self.filemenu.add_command(label="Logout", command=self.logout_eh)
        self.filemenu.add_command(label="Exit", command=self.show_exit_message_eh)
        self.menubar.add_cascade(label="File", menu=self.filemenu)
        self.helpmenu = Menu(self.menubar, tearoff=0)
        self.helpmenu.add_command(label="Description", command=self.open_description_window_eh)
        self.helpmenu.add_command(label="About...", command=self.open_about_window_eh)
        self.menubar.add_cascade(label="Help", menu=self.helpmenu)
        self.config(menu=self.menubar)
        self.protocol('WM_DELETE_WINDOW', self.show_exit_message_eh)

    def go_button_clicked(self):
        game = self.game
        if game.new_game_requested:
            game.new_game_requested = False
            self.new_game_window()
            return
        # self.lb3_['text'] = "Previous set: " + str(len(game.previous_all_set))
        # self.status_label["text"] = f"Attempts: {str(self.game.attempts)}      Duration 00:00:{self.count}"

        if game.attempts == 0:
            game.get_new_guess_proposal()
            game.think_of_number_for_you()
            game.attempts += 1
            game.start_timestamp = time()
            game.game_started = True
            if game.dual_game_enabled:
                self.change_data_on_window_dual_game()
                self.time_counter()
            else:
                self.change_data_on_window_mono_game()
            if not game.your_string_for_automation_game:
                self.my_cows_label["state"] = "normal"
                self.my_cows_entry["state"] = "normal"
                self.my_bulls_label["state"] = "normal"
                self.my_bulls_entry["state"] = "normal"
            else:
                self.my_cows_label["state"] = "disabled"
                self.my_cows_entry["state"] = "disabled"
                self.my_bulls_label["state"] = "disabled"
                self.my_bulls_entry["state"] = "disabled"
            if game.dual_game_enabled:
                self.my_upper_label["state"] = "normal"
                self.your_upper_label["state"] = "normal"
                self.your_guess_entry["state"] = "normal"
                self.your_cows_label["state"] = "normal"
                self.your_bulls_label["state"] = "normal"
            return
        self.update_status_label()

        if game.your_string_for_automation_game:
            game.my_cows, game.my_bulls = game.calc_bulls_and_cows(
                game.your_string_for_automation_game, game.guess_proposal)
        else:
            my_cows_entered = self.my_cows_entry.get().strip()
            my_bulls_entered = self.my_bulls_entry.get().strip()
            try:
                game.validate_cows_and_bulls(my_cows_entered, my_bulls_entered, game.capacity)
            except Exception as exc:
                MessageBox.show_message(self, ErrorMessage(str(exc)))
                return
            game.my_cows = int(my_cows_entered)
            game.my_bulls = int(my_bulls_entered)
        if game.dual_game_enabled and game.attempts > 0:
            your_guess_entered = self.your_guess_entry.get().strip()
            try:
                game.validate_your_string(game.capacity, your_guess_entered)
                your_result = game.your_guess(your_guess_entered)
            except Exception as exc:
                MessageBox.show_message(self, ErrorMessage(str(exc)))
                return
        else:
            your_result = False
        try:
            my_result = game.my_guess()
        except FinishedNotOKException:
            self.finish_game_on_main_window(0)
            return
        except Exception as exc:
            MessageBox.show_message(self, ErrorMessage(str(exc)))
            return
        if my_result and not your_result:
            self.finish_game_on_main_window(1)
            return
        if your_result and not my_result:
            self.finish_game_on_main_window(2)
            return
        if your_result and my_result:
            self.finish_game_on_main_window(3)
            return
        if game.dual_game_enabled:
            self.change_data_on_window_dual_game()
        else:
            self.change_data_on_window_mono_game()

    def time_counter(self):
        if not self.game.game_started:
            return
        seconds = self.count % 60
        minutes = int(self.count / 60)
        hours = int(self.count / 3600)
        self.status_label["text"] = f"Attempts: {self.game.attempts}      " \
                                    f"Duration {hours:02d}:{minutes:02d}:{seconds:02d}"
        self.count += 1
        self.after(1000, self.time_counter)

    def mouse_function_hide(self, event):
        self.lb3_.pack_forget()

    def mouse_function_show(self, event):
        self.lb3_.pack(fill='none', side='bottom')

    def new_game_clicked_eh(self):
        if not self.game.game_started: return
        self.game.game_initials()
        self.new_game_window()

    def new_game_window(self):
        game = self.game
        game.game_initials()
        if game.dual_game_enabled:
            self.enable_dual_game()
        else:
            self.enable_mono_game()
        game.think_of_number_for_you()  # ???

    @staticmethod
    def disable_event():
        pass

    def donothing(self):
        pass

    def finish_game_on_main_window(self, game_result_code):
        game = self.game
        game.finish_timestamp = time()
        game.game_started = False
        if game_result_code == 0:  ####
            self.upper_label['text'] = "You have broken my mind! Please be more carefull!\nThink of a new number!"
            self.upper_label['fg'] = '#f00'
        elif game_result_code == 1:
            self.upper_label['text'] = "YAHOO! I've won! Thank you the for interesting game!\n" \
                                       "Attempts: " + str(self.game.attempts)
            self.upper_label['fg'] = '#00f'
        elif game_result_code == 2:
            self.upper_label['text'] = "Today is your day! You've won! Congrats!\n" \
                                       "Attempts: " + str(self.game.attempts)
            self.upper_label['fg'] = '#00f'
        else:
            self.upper_label['text'] = "We've ended this game in a tie!..\n" \
                                       "Attempts: " + str(self.game.attempts)
            self.upper_label['fg'] = '#00a'
        self.go_button['text'] = 'Play again!'
        self.game.new_game_requested = True
        # self.lb3_['text'] = "Previous set: " + str(len(self.game.previous_all_set))
        self.my_cows_entry.delete(0, "end")
        self.my_bulls_entry.delete(0, "end")
        self.my_cows_label["state"] = "disabled"
        self.my_cows_entry["state"] = "disabled"
        self.my_bulls_label["state"] = "disabled"
        self.my_bulls_entry["state"] = "disabled"
        if self.game.dual_game_enabled:
            self.my_upper_label["state"] = "disabled"
            self.your_upper_label["state"] = "disabled"
            self.your_guess_entry.delete(0, "end")
            self.your_guess_entry["state"] = "disabled"
            self.your_cows_label["state"] = "disabled"
            self.your_bulls_label["state"] = "disabled"
            self.add_item_to_my_and_your_history_frame()
            if game_result_code > 0:
                game.write_fl_to_db(game_result_code)
        else:
            self.add_item_to_my_history_frame()

    def change_data_on_window_mono_game(self):
        self.my_cows_entry.delete(0, "end")
        self.my_bulls_entry.delete(0, "end")
        self.upper_label['text'] = 'I guess your number is: ' + self.game.guess_proposal
        self.upper_label['fg'] = '#000'
        self.go_button["text"] = "OK!"
        # self.attempts_label['text'] = 'Attempts: ' + str(self.game.attempts)
        self.update_status_label()
        if self.game.attempts > 1:
            self.add_item_to_my_history_frame()

    def add_item_to_my_history_frame(self):
        game = self.game
        h = self.initial_main_height + self.string_interval_history_frame * (len(game.my_history_list) - 1)
        # if not self.my_history_frame:
        #     self.my_history_frame = LabelFrame(self, text='History of attempts', labelanchor='n', font='arial 8',
        #                                        padx='80')
        self.my_history_frame.place(x=90, y=130)
        self.geometry(f'{self.initial_main_width}x{h}')
        t0 = game.my_history_list[-1]
        my_frame_lb = Label(self.my_history_frame, text=str(t0[0]) + "  " + str(t0[1]) + "." + str(t0[2]),
                            font='arial 9')
        my_frame_lb.pack()
        self.my_history_lb_list.append(my_frame_lb)

    def change_data_on_window_dual_game(self):
        self.upper_label["text"] = choice(Game.good_mood_phrases)
        self.my_cows_entry.delete(0, "end")
        self.my_bulls_entry.delete(0, "end")
        self.your_guess_entry.delete(0, "end")
        self.my_upper_label['text'] = 'I guess your number is: ' + self.game.guess_proposal
        self.upper_label['fg'] = '#000'
        # self.attempts_label['text'] = 'Attempts: ' + str(self.game.attempts)
        # self.status_label["text"] = f"Attempts: {str(self.game.attempts)}      Duration 00:00:{self.count}"
        self.update_status_label()
        self.go_button["text"] = "OK!"
        if self.game.attempts > 1:
            self.your_cows_label["text"] = "You guessed cows: " + str(self.game.your_cows) + "\n"
            self.your_bulls_label["text"] = "You guessed bulls: " + str(self.game.your_bulls) + "\n"
            self.add_item_to_my_and_your_history_frame()

    def add_item_to_my_and_your_history_frame(self):
        game = self.game
        h = self.initial_main_height + self.string_interval_history_frame * (len(game.my_history_list) - 1)
        # if not self.my_history_frame:
        #     self.my_history_frame = LabelFrame(self, text='History of attempts', labelanchor='n', font='arial 8',
        #                                        padx='80')
        self.my_history_frame.pack()
        self.your_history_frame.pack()
        self.geometry(f'{self.initial_main_width}x{h}')
        item = game.my_history_list[-1]
        my_frame_lb = Label(self.my_history_frame, text=str(item[0]) + "  " + str(item[1]) + "." + str(item[2]),
                            font='arial 9')
        my_frame_lb.pack()
        self.my_history_lb_list.append(my_frame_lb)
        item = game.your_history_list[-1]
        your_frame_lb = Label(self.your_history_frame, text=str(item[0]) + "  " + str(item[1]) + "." + str(item[2]),
                              font='arial 9')
        your_frame_lb.pack()
        self.your_history_lb_list.append(your_frame_lb)
        self.go_button.place(x=int(1.4 * self.initial_main_width / 2 - 200),
                             y=240 + self.string_interval_history_frame * (len(game.my_history_list) - 1))

    def open_login_window(self):
        login_window = LoginWindow(self)
        login_window.main_win = self
        login_window.game = self.game
        login_window.geometry(str(login_window.width) + 'x' + str(login_window.height))
        login_window.resizable(0, 0)
        # self.login_window.wm_attributes('-topmost', 'yes')
        login_window.label0 = Label(login_window, text='Please enter your login and password: ',
                                    font='TimesNewRoman 12', fg='#e0e')
        login_window.label0.place(x=40, y=10)
        login_window.login_label = Label(login_window, text='Login:', font='Arial 10')
        login_window.login_label.place(x=10, y=40)
        login_window.login_entry = Entry(login_window, width=25, font='Arial 10', state='normal')
        login_window.login_entry.place(x=100, y=40)
        login_window.password_label = Label(login_window, text='Password:', font='arial 10')
        login_window.password_label.place(x=10, y=80)
        login_window.password_entry = Entry(login_window, width=25, font='Arial 10', show='*', state='normal')
        login_window.password_entry.place(x=100, y=80)
        login_window.login_button = Button(login_window, text='Log in', font='arial 10',
                                           command=login_window.authenticate_user_eh)
        login_window.login_button.place(x=30, y=120)
        login_window.new_user_button = Button(login_window, text='New user...', font='arial 10',
                                              command=login_window.open_users_window_eh)
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

    def open_about_window_eh(self):
        about_window = AboutWindow(self)
        about_window.game = self.game
        about_window.geometry(f'{about_window.win_width}x{about_window.win_height}')
        about_window.resizable(0, 0)
        about_window.lb1 = Label(
            about_window, text='This game is created by Eugene Dolgov. \nAll rights reserved \u00a9 2021.',
            font='arial 10')
        about_window.lb1.place(x=20, y=10)
        about_window.button = Button(about_window, text='OK', command=lambda: about_window.destroy())
        about_window.button.place(x=130, y=60)
        about_window.lb1.bind("<Double-Button-3>", about_window.input_your_string_for_automation_game)
        about_window.button.bind("<Double-Button-3>", about_window.show_my_guessed_number)
        about_window.transient(self)
        about_window.grab_set()
        about_window.focus_set()

    def open_description_window_eh(self):
        text = "It's a modified version of classical game Bulls and Cows. " \
               "One of participants thinks of a number which consists of " \
               "non-repeatable digits, and the second participant tries " \
               "to guess the number proposing variants. The first gamer " \
               "compares the original number and the proposed one and " \
               "reports to the second gamer two values: " \
               "the overall amount of the coincident digits (cows) " \
               "and the amount of the coincident digits " \
               "which have the right position(bulls)."
        MessageBox.show_message(self, InfoMessage(text))

    def open_setting_window_eh(self):
        # if self.text1['state'] != 'disabled' or self.text2['state'] != 'disabled':
        #     return
        def callback(sv):
            if not self.game.game_started and not self.game.new_game_requested:
                setting_window.cap_button['state'] = 'normal'
                setting_window.cap_entry["state"] = "normal"

        setting_window = SettingWindow(self)
        setting_window.game = game = self.game
        setting_window.main_window = self
        setting_window.title("Settings")
        setting_window.geometry(str(setting_window.width) + 'x' + str(setting_window.height))
        setting_window.resizable(0, 0)
        setting_window.cap_label = Label(setting_window, text='Capacity:', font='arial 8', anchor="e")
        setting_window.cap_label.place(x=10, y=13)
        setting_window.cap_button = Button(setting_window, text='Apply', font='arial 7',
                                           command=setting_window.get_capacity)
        setting_window.cap_button.place(x=90, y=10)
        sv = StringVar()
        sv.trace("w", lambda name, index, mode, sv=sv: callback(sv))
        setting_window.cap_entry = Entry(setting_window, width=3, font='Arial 8', state='normal',
                                         textvariable=sv)
        setting_window.cap_entry.place(x=65, y=13)
        setting_window.cap_entry.delete('0', 'end')
        setting_window.cap_entry.insert('0', game.capacity)
        # setting_window.cap_entry['state'] = 'disabled'
        setting_window.dual_game_label = Label(setting_window, text='Dual game: ', font='arial 8')
        setting_window.dual_game_label.place(x=10, y=45)
        setting_window.cb_variable = BooleanVar()
        setting_window.cb_variable.set(int(game.dual_game_enabled))
        setting_window.dual_game_checkbox = Checkbutton(setting_window, variable=setting_window.cb_variable,
                                                        onvalue=1, offvalue=0,
                                                        command=setting_window.switch_dual_game)
        setting_window.dual_game_checkbox.place(x=70, y=40)
        setting_window.dual_game_checkbox.select() if game.dual_game_enabled else \
            setting_window.dual_game_checkbox.deselect()
        if game.game_started:
            setting_window.cap_button["state"] = "disabled"
            setting_window.cap_entry["state"] = "disabled"
            setting_window.dual_game_checkbox["state"] = "disabled"
        setting_window.transient(self)
        setting_window.grab_set()
        setting_window.focus_set()
        # self.window.wait_window()

    def open_fixture_list_window_eh(self):
        game = self.game
        if not game.dual_game_enabled:
            return
        try:
            fl_data = game.get_data_for_fixture_table()
        except Exception as exc:
            MessageBox.show_message(self, ErrorMessage(str(exc)))
            return
        fixture_list_window = FixtureListTreeview(self, fl_data)
        button = Button(fixture_list_window, text="Close", width=10,
                        command=lambda: fixture_list_window.destroy())
        button.pack(side="bottom")

    def show_exit_message_eh(self):
        text = "Are you sure you want to quit?"
        MessageBox.show_logout_message(self, WarningMessage(text), False)

    def enable_mono_game(self):
        game = self.game
        self.destroy_previous_window_items()
        self.windows_initials()
        self.initial_main_width = self.mono_game_main_width
        self.initial_main_height = self.mono_game_main_height
        self.geometry(f'{self.initial_main_width}x{self.initial_main_height}')
        self.resizable(0, 0)
        self.title("Bulls and Cows Game")
        self.upper_label = Label(self, text="Think of a number with " + str(game.capacity) + " unique digits!",
                                 font='arial 12')
        self.upper_label.bind("<Double-Button-1>", self.mouse_function_hide)
        self.upper_label.bind("<Double-Button-3>", self.mouse_function_show)
        self.upper_label['fg'] = MainWin.upper_label_normal_color
        # self.upper_label.place(x=70, y=5)
        self.upper_label.pack()
        self.my_cows_label = Label(self, text='Enter a number of "cows": ', font='arial 10')
        self.my_cows_label.place(x=105, y=40)
        self.my_cows_entry = Entry(self, width=3, font='Arial 8', state='disabled')
        self.my_cows_entry.place(x=270, y=40)
        self.my_bulls_label = Label(self, text='Enter a number of "bulls": ', font='arial 10')
        self.my_bulls_label.place(x=105, y=70)
        self.my_bulls_entry = Entry(self, width=3, font='Arial 8', state='disabled')
        self.my_bulls_entry.place(x=270, y=70)
        self.go_button = Button(self, text="OK! Go on!", width=20, command=self.go_button_clicked)
        self.go_button.place(x=110, y=100)
        self.my_history_frame = LabelFrame(self, text='History of attempts', labelanchor='n', font='arial 8',
                                           padx='80')
        self.lb3_ = Label(self, text="Previous set: " + str(len(game.total_set)), font='arial 5')
        #  lb3_.pack(fill='none', side='bottom')
        #  lb3_.pack_forget()
        # self.attempts_label = Label(self, text="Attempts: " + str(game.attempts), font='arial 8')
        # self.attempts_label.pack(side="bottom")
        self.status_label = Label(self, text=f"Attempts: {str(game.attempts)}", font='arial 10', bd=1, relief=SUNKEN,
                                  anchor=E)
        self.status_label.pack(fill=X, side=BOTTOM, ipady=2)

    def enable_dual_game(self):
        game = self.game
        self.destroy_previous_window_items()
        self.windows_initials()
        self.initial_main_width = self.dual_game_main_width - 10
        self.initial_main_height = self.dual_game_main_height
        self.geometry(f'{self.initial_main_width}x{self.initial_main_height}')
        self.resizable(0, 0)
        self.title("Bulls and Cows Game")
        self.upper_label = Label(self, text="Think of a number with "
                                            + str(game.capacity) + " unique digits!\n"
                                                                   "And I will think of a number to guess for you!",
                                 font='arial 12')
        self.upper_label.bind("<Double-Button-1>", self.mouse_function_hide)
        self.upper_label.bind("<Double-Button-3>", self.mouse_function_show)
        self.upper_label['fg'] = MainWin.upper_label_normal_color
        # self.upper_label.place(x=70, y=5)
        self.upper_label.pack()
        self.my_outer_frame = LabelFrame(self, text='My part', labelanchor='n', font='arial 8', padx='40', pady='5')
        self.my_outer_frame.place(x=15, y=50)
        self.my_upper_label = Label(self.my_outer_frame, text="I guess your number is: " + "    ", font='arial 11')
        self.my_upper_label.pack()
        self.my_upper_label["state"] = "disabled"
        self.my_cows_label = Label(self.my_outer_frame, text="Enter the number of cows: ", font='arial 11')
        self.my_cows_label.pack()
        self.my_cows_label["state"] = "disabled"
        self.my_cows_entry = Entry(self.my_outer_frame, width=3, font='Arial 8', state='disabled')
        self.my_cows_entry.pack()
        self.my_cows_entry["state"] = "disabled"
        self.my_bulls_label = Label(self.my_outer_frame, text="Enter the number of bulls: ", font='arial 11')
        self.my_bulls_label.pack()
        self.my_bulls_label["state"] = "disabled"
        self.my_bulls_entry = Entry(self.my_outer_frame, width=3, font='Arial 8', state='disabled')
        self.my_bulls_entry.pack()
        self.my_bulls_entry["state"] = "disabled"
        self.my_align_label = Label(self.my_outer_frame, text="\n", font='arial 3')
        self.my_align_label.pack()
        self.my_history_frame = LabelFrame(self.my_outer_frame, text='History of attempts', labelanchor='n',
                                           font='arial 8', padx='40')
        self.my_history_frame.pack()
        # self.lb002 = Label(self.my_history_frame, text="1111 1.1", font='arial 9')
        # self.lb002.pack()
        self.your_outer_frame = LabelFrame(self, text='Your part', labelanchor='n', font='arial 8', padx='60', pady='3')
        self.your_outer_frame.place(x=275, y=50)
        self.your_upper_label = Label(self.your_outer_frame, text="Enter your guess: ", font='arial 11')
        self.your_upper_label.pack()
        self.your_upper_label["state"] = "disabled"
        self.your_guess_entry = Entry(self.your_outer_frame, width=game.capacity + 2, font='Arial 10', state='disabled')
        self.your_guess_entry.pack()
        self.your_guess_entry["state"] = "disabled"
        self.your_cows_label = Label(self.your_outer_frame, text="You guessed cows: \n", font='arial 11')
        self.your_cows_label.pack()
        self.your_cows_label["state"] = "disabled"
        # self.cows_entry = Entry(self.your_outer_frame, width=3, font='Arial 8', state='disabled')
        # self.cows_entry.pack()
        self.your_bulls_label = Label(self.your_outer_frame, text="You guessed bulls: \n", font='arial 11')
        self.your_bulls_label.pack()
        self.your_bulls_label["state"] = "disabled"
        # self.bulls_entry = Entry(self.your_outer_frame, width=3, font='Arial 8', state='disabled')
        # self.bulls_entry.pack()
        self.your_history_frame = LabelFrame(self.your_outer_frame, text='History of attempts', labelanchor='n',
                                             font='arial 8', padx='40')
        self.your_history_frame.pack()
        # self.lb001 = Label(self.your_history_frame, text="1111 1.1", font='arial 9')
        # self.lb001.pack()
        self.go_button = Button(self, text="OK! Go on!", width=20, command=self.go_button_clicked)
        self.go_button.place(x=int(1.4 * self.initial_main_width / 2 - 200), y=230)
        # self.go_button.pack(side="bottom")
        # self.attempts_label = Label(self, text="Attempts: " + str(game.attempts), font='arial 10')
        # self.attempts_label.pack(side="bottom")
        self.status_label = Label(self, text=f"Attempts: {str(game.attempts)}      Duration 00:00:00", font='arial 10',
                                  bd=1, relief=SUNKEN, anchor=E)
        self.status_label.pack(fill=X, side=BOTTOM, ipady=2)

    def destroy_previous_window_items(self):
        if self.my_outer_frame:
            self.my_outer_frame.destroy()
        if self.your_outer_frame:
            self.your_outer_frame.destroy()
        if self.my_history_frame:
            self.my_history_frame.destroy()
        if self.your_history_frame:
            self.your_history_frame.destroy()
        if self.upper_label:
            self.upper_label.destroy()
        if self.go_button:
            self.go_button.destroy()
        if self.attempts_label:
            self.attempts_label.destroy()
        if self.my_cows_label:
            self.my_cows_label.destroy()
        if self.my_cows_entry:
            self.my_cows_entry.destroy()
        if self.my_bulls_label:
            self.my_bulls_label.destroy()
        if self.my_bulls_entry:
            self.my_bulls_entry.destroy()
        if self.status_label:
            self.status_label.destroy()
        if self.lb3_:
            self.lb3_.destroy()

    def update_status_label(self):
        text = self.status_label["text"]
        new_text = re.sub(r"(Attempts:\s+)(\d+)", r"\g<1>" + str(self.game.attempts), text)
        self.status_label["text"] = new_text

    def logout_eh(self):
        if self.game.game_started:
            text = "Are you sure you want to finish the game and logout?"
        else:
            text = "Are you sure you want to logout?"
        MessageBox.show_logout_message(self, WarningMessage(text), True)

    def close(self):
        self.destroy()
        self.quit()


class SettingWindow(Toplevel):
    width = 170
    height = 70

    def __init__(self, parent_window):
        super().__init__(parent_window)
        self.parent_window = parent_window

    def get_capacity(self):
        new_capacity = self.cap_entry.get().strip()
        if not (new_capacity.isdigit()):
            return
        new_capacity = int(new_capacity)
        if new_capacity < 3 or new_capacity > 6:
            return
        self.game.capacity = new_capacity
        if self.game.dual_game_enabled:
            self.main_window.upper_label["text"] = "Think of a number with " + str(new_capacity) \
                                                   + " unique digits!\nAnd I will think of " \
                                                     "a number to guess for you!"
        else:
            self.main_window.upper_label['text'] = "Think of a number with " \
                                                   + str(new_capacity) + " unique digits!"
        self.main_window.upper_label['fg'] = MainWin.upper_label_normal_color
        self.cap_button['state'] = 'disabled'
        self.cap_entry["state"] = "disabled"
        # self.setting_window.grab_release()
        # self.setting_window.withdraw()

    def switch_dual_game(self):
        self.game.dual_game_enabled = bool(self.cb_variable.get())
        if self.game.dual_game_enabled:
            self.main_window.enable_dual_game()
        else:
            self.main_window.enable_mono_game()
        # self.main_window.geometry(f"{2 * self.main_window.initial_main_width}x{self.main_window.initial_main_height}")


class AboutWindow(Toplevel):
    win_width = 300
    win_height = 111

    def __init__(self, parent_window):
        super().__init__(parent_window)
        self.your_string_entry = None
        self.parent_window = parent_window

    def input_your_string_for_automation_game(self, event):
        game = self.game
        if game.game_started or game.new_game_requested or game.dual_game_enabled: return
        if not self.your_string_entry:
            self.geometry(f'{self.win_width}x{self.win_height + 20}')
            self.your_string_entry = Entry(self, width=game.capacity + 2, font='Arial 8', state='normal')
            self.your_string_entry.place(x=135, y=100)
            return
        your_string = self.your_string_entry.get().strip()
        if not your_string or not your_string.isdigit() or len(your_string) != game.capacity \
                or len(set(list(your_string))) != len(your_string):
            return
        game.your_string_for_automation_game = your_string
        self.your_string_entry.delete(0, 'end')
        self.your_string_entry.destroy()
        self.your_string_entry = None
        self.geometry(f'{self.win_width}x{self.win_height}')
        self.automate_answer()

    def automate_answer(self):
        game = self.game
        iteration = 1
        while not (game.my_cows == game.capacity and game.my_bulls == game.capacity):
            self.parent_window.go_button_clicked()
            iteration += 1
            # actually it's unnecessary because automation guess procedure works OK but just for safety
            if iteration > 50:
                break

    def show_my_guessed_number(self, event):
        if self.game.dual_game_enabled:
            self.button["text"] = self.game.my_string_for_you


class DescriptionWindow(Toplevel):
    def __init__(self, parent_window):
        super().__init__(parent_window)
        self.transient(parent_window)
        self.grab_set()
        self.focus_set()


class FixtureListTreeview(Toplevel):
    def __init__(self, parent_window, fl_data):
        super().__init__(parent_window)
        self.transient(parent_window)
        self.grab_set()
        self.focus_set()
        # fixture_list_window.geometry('700x300')
        self.resizable(0, 0)
        self.title("Fixture List")
        fl_style = ttk.Style()
        fl_style.theme_use("default")
        fl_style.configure("Treeview",
                           background="silver",
                           foreground="black",
                           rowheight=25,
                           fieldbackground="silver")
        fl_style.map("Treeview", background=[("selected", "grey")])
        fl_frame = ttk.Frame(self)
        fl_frame.pack()
        fl_scroll = ttk.Scrollbar(fl_frame, orient="vertical")
        fl_scroll.pack(side="right", fill="y")
        fl_tree = ttk.Treeview(fl_frame, selectmode="browse", yscrollcommand=fl_scroll.set)
        fl_tree.pack()
        fl_tree["columns"] = ("first_name", "last_name", "login", "winner",
                              "attempts", "date", "duration")
        fl_tree.column("#0", width=0, anchor="c", stretch="no")
        fl_tree.column("first_name", width=120, anchor="c")
        fl_tree.column("last_name", width=120, anchor="c")
        fl_tree.column("login", width=120, anchor="c")
        fl_tree.column("winner", width=70, anchor="c")
        fl_tree.column("attempts", width=90, anchor="c")
        fl_tree.column("date", width=120, anchor="c")
        fl_tree.column("duration", width=90, anchor="c")
        fl_tree.heading("#0", text="")
        fl_tree.heading("first_name", text="First Name")
        fl_tree.heading("last_name", text="Last Name")
        fl_tree.heading("login", text="Login")
        fl_tree.heading("winner", text="Winner")
        fl_tree.heading("attempts", text="Attempts")
        fl_tree.heading("date", text="Date")
        fl_tree.heading("duration", text="Duration")
        fl_scroll.configure(command=fl_tree.yview)
        self.fl_tree = fl_tree
        self.populate_treeview(fl_data)

    def populate_treeview(self, fl_data):
        for row in fl_data:
            self.fl_tree.insert(parent="", index="end", text="", values=row)


class MessageBox:
    messagebox = None

    def __init__(self, parent_window, msg):
        self.parent_window = parent_window

    @staticmethod
    def show_message(parent_window, msg):
        def close():
            if parent_window:
                parent_window.grab_set()
            if isinstance(parent_window, LoginWindow) and isinstance(msg, InfoMessage):
                parent_window.destroy()
                # self.wm_attributes('-topmost', 'yes')
                # self.parent_window.grab_set()
                # self.parent_window.focus_set()
            messagebox.destroy()

        text = msg.text.strip()
        initial_text = text.split("\n")[0]  # ???
        text, width, height = MessageBox.format_text(initial_text)  ###
        messagebox = Toplevel(parent_window) if parent_window else Tk()
        messagebox.title(msg.title)
        # if parent_window: width = width + 30
        messagebox.geometry(str(width) + 'x' + str(height))
        messagebox.resizable(0, 0)
        # label_pic = PhotoImage(file="error_pic.gif")
        msgbox_pic = Label(messagebox, image=msg.label_pic)
        msgbox_lb = Label(messagebox, text=text, font='arial 10', anchor='w')
        msgbox_button_frame = Frame(messagebox, height=32, width=75)
        msgbox_button_frame.pack_propagate(0)
        msgbox_bt = Button(msgbox_button_frame, text="OK", width=10, command=close)
        msgbox_bt.pack()
        messagebox.protocol('WM_DELETE_WINDOW', close)
        if parent_window:
            msgbox_pic.pack(side="left", padx=20)
            msgbox_lb.place(x=90, y=25)
            msgbox_button_frame.place(x=int(width / 2) - 30, y=height - 40)
            messagebox.transient(parent_window)
            messagebox.grab_set()
            messagebox.focus_set()
        else:
            msgbox_pic.pack(side="left", padx=20)
            msgbox_lb.place(x=90, y=25)
            msgbox_button_frame.place(x=int(width / 2), y=height - 40)
            # msgbox_lb.pack(side="top", pady=10)
            # msgbox_button_frame.pack(side="bottom", pady=20)
            messagebox.mainloop()

    @staticmethod
    def show_logout_message(parent_window, msg, is_logout):
        def yes():
            if isinstance(parent_window, MainWin):
                parent_window.close()
            else:
                if isinstance(parent_window, UsersWindow):
                    parent_window.proceed_deleting(parent_window.login_for_deleting)
                    parent_window.main_win.close()
            if is_logout:
                run()

        text, width, height = MessageBox.format_text(msg.text.strip())
        msgbox = Toplevel(parent_window)
        msgbox.title("")
        msgbox.geometry(str(width) + 'x' + str(height))
        msgbox.resizable(0, 0)
        msgbox_pic = Label(msgbox, image=msg.label_pic)
        msgbox_pic.pack(side="left", padx=20)
        msgbox_lb = Label(msgbox, text=text, font='arial 10', anchor='w')
        msgbox_lb.place(x=80, y=20)
        msgbox_yes_bt = Button(msgbox, text="Yes", width=8, command=yes)
        msgbox_yes_bt.place(x=int(width / 2) - 70, y=height - 50)  # continue from this
        msgbox_no_bt = Button(msgbox, text="No", width=8, command=msgbox.destroy)
        msgbox_no_bt.place(x=int(width / 2) + 40, y=height - 50)
        msgbox.transient(parent_window)
        msgbox.grab_set()
        msgbox.focus_set()

    @staticmethod
    def format_text(text):
        r_list = []
        longest_length = 0
        maximum_length = 70
        if len(text) <= maximum_length:
            total_text = text
            longest_length = len(total_text)
        else:
            initial_text_list = text.split(" ")
            result_str = ''
            for c in initial_text_list:
                if len(result_str + " " + c) < maximum_length:
                    result_str += " " + c
                else:
                    result_str += " " + c
                    longest_length = max(len(result_str), longest_length)
                    r_list.append(result_str)
                    result_str = ""
            if len(initial_text_list) != len(r_list):
                r_list.append(result_str)
            total_text = "\n".join(r_list)
        if len(r_list) == 0:
            number_of_rows = 1
        else:
            number_of_rows = len(r_list)
        # width = longest_length * 10 + 50 - (longest_length//35)*55
        # width = longest_length * (11 - longest_length//20) + 50
        width = 80 + longest_length * 8 - int(60 * longest_length / maximum_length)
        height = 95 + number_of_rows * 16
        return total_text, width, height


class ExitMessage:
    exitmessage_width = 350
    exitmessage_height = 100
    text = "Are you sure you want to quit?"

    def __init__(self, parent_window):
        self.parent_window = parent_window


class BaseMessage:
    def __init__(self, msg):
        self.text = str(msg)


class InfoMessage(BaseMessage):
    title = "Info"

    def __init__(self, msg):
        super().__init__(msg)
        self.title = InfoMessage.title
        self.label_pic = LabelPics.info_pic


class WarningMessage(BaseMessage):
    title = "Warning"

    def __init__(self, msg):
        super().__init__(msg)
        self.title = WarningMessage.title
        self.label_pic = LabelPics.warning_pic


class ErrorMessage(BaseMessage):
    title = "Error"

    def __init__(self, msg):
        super().__init__(msg)
        self.title = ErrorMessage.title
        self.label_pic = LabelPics.error_pic


class BnCException(Exception):
    def __init__(self, msg):
        super().__init__()
        self.msg = msg

    def __repr__(self):
        return "{}".format(self.msg)

    def __str__(self):
        return "{}".format(self.msg)


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


class LabelPics:
    error_pic = None
    info_pic = None
    warning_pic = None


def run():
    game = Game()
    main_win = MainWin()
    main_win.game = game
    if game.dual_game_enabled:
        main_win.enable_dual_game()
    else:
        main_win.enable_mono_game()
    main_win.show_main_window_menu()
    main_win.open_login_window()
    main_win.mainloop()


def read_config():
    with open(CONFIG_PATH) as f:
        raw_config = yaml.load(f, Loader=SafeLoader)
    Game.email_messages = dict()
    Game.email_messages["welcome"] = dict()
    Game.email_messages["pincode"] = dict()
    Game.email_messages["welcome"]["text"] = raw_config["welcome"]["text"]
    Game.email_messages["welcome"]["html"] = raw_config["welcome"]["html"]
    Game.email_messages["welcome"]["subject"] = raw_config["welcome"]["subject"]
    Game.email_messages["pincode"]["text"] = raw_config["pincode"]["text"]
    Game.email_messages["pincode"]["html"] = raw_config["pincode"]["html"]
    Game.email_messages["pincode"]["subject"] = raw_config["pincode"]["subject"]
    Game.db_conn_string_pre = raw_config["db_connection_string_prefix"]
    Game.default_db_user = raw_config["default_db_user"]
    Game.default_db_password = raw_config["default_db_password"]
    Game.db_socket = raw_config["db_socket"]
    Game.admin_user = raw_config["admin_user"]
    Game.smtp_address = raw_config["smtp_address"]
    Game.bnc_email = raw_config["bnc_email"]
    Game.ssl_port = raw_config["ssl_port"]
    Game.smtp_password = raw_config["smtp_password"]
    Game.phrases_path = raw_config["phrases_path"]


def read_phrases():
    try:
        with open(Game.phrases_path) as f:
            data = f.read()
        lst = data.split("\n")
        if len(lst):
            Game.good_mood_phrases = lst
        else:
            lst = ["Wishing you and me an interesting game!"]
    except Exception:
        Game.good_mood_phrases = ["Wishing you and me an interesting game!"]
    Game.good_mood_phrases = [e for e in Game.good_mood_phrases if len(e) < 78]


def get_salt():
    random_string_chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    salt_entropy = 128
    char_count = math.ceil(salt_entropy / math.log2(len(random_string_chars)))
    return "".join(choice(random_string_chars) for i in range(char_count))


def encrypt_password(password, salt_str=None, iterations=320000, algorithm="pbkdf2_sha256"):
    salt_str = salt_str or get_salt()
    salt = salt_str.encode("utf-8", "strict")
    password = password.encode("utf-8", "strict")
    password_hash = hashlib.pbkdf2_hmac(hashlib.sha256().name, password, salt, iterations, None)
    password_hash = base64.b64encode(password_hash).decode("ascii").strip()
    return "%s$%d$%s$%s" % (algorithm, iterations, salt_str, password_hash)


def check_password(password, password_from_db):
    algorithm, iterations, salt_str, password_hash = password_from_db.split("$", 3)
    encrypted_2 = encrypt_password(password, salt_str, iterations)
    if password_from_db != encrypted_2:
        raise IncorrectPasswordException



read_config()
read_phrases()
if __name__ == '__main__':
    run()
