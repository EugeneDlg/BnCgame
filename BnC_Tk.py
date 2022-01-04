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
DB_CONN_STRING = "postgresql+psycopg2://postgres:dFAkc2E3TWw=@127.0.0.1:5432/bnc"
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


class Game:
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

        self.game_started = False
        self.new_game_requested = False
        self.loggedin_user = None
        self.admin_needed = False
        # self.main_win = None
        # self.menubar = None
        # self.filemenu = None
        # self.helpmenu = None
        # self.lb0 = None
        # self.lb1 = None
        # self.text1 = None
        # self.lb2 = None
        # self.text2 = None
        # self.button = None
        # self.lb3_ = None
        # self.fr0 = None
        # self.lb4 = None
        self.your_string_entry = None
        self.user_privileges = None

        # self.setting_window = None
        # self.help_window = None
        # self.login_window = None
        # self.login_window_lb0 = None
        # self.setting_window_cap_lb = None
        # self.setting_window_cap_en = None
        # self.setting_window_cap_bt = None
        # self.setting_window_lf0 = None
        # self.setting_window_lf1 = None
        # self.setting_window_un_lb = None
        # self.setting_window_un_en = None
        # self.setting_window_pw_lb = None
        # self.setting_window_pw_en = None
        # self.setting_window_cr_bt = None
        # self.setting_window_dl_bt = None
        # self.about_lb1 = None

        # self.users_window = None
        # self.users_window_login_lb = None
        # self.users_window_login_en = None
        # self.users_window_pass_lb = None
        # self.users_window_pass_en = None
        # self.users_window_firstname_lb = None
        # self.users_window_firstname_en = None
        # self.users_window_lastname_lb = None
        # self.users_window_lastname_en = None
        # self.users_window_pass_lb1 = None
        # self.users_window_pass_en1 = None
        # self.users_window_pass_lb2 = None
        # self.users_window_pass_en2 = None
        # self.password_en1 = None
        # self.password_en2 = None
        # self.users_window_create_bt = None
        # self.users_window_delete_bt = None
        # self.users_window_modify_bt = None
        # self.users_window_show_pass_bt = None
        # self.users_window_email_lb = None
        # self.users_window_email_en = None
        # self.login_window_rp_bt = None

    @staticmethod
    def load_logged_user_info(loggedin_user):
        try:
            session = Game.get_db_session()
            r = session.query(BnCUsers).filter_by(login=loggedin_user).first()
            session.close()
        except Exception:
            try:
                session.rollback()
            except:
                pass
            raise
        # match = re.search(r"firstname=\'(.*)\', lastname=\'(.*)\', email=\'(.*?)\'", str(r))
        login = loggedin_user
        firstname = str(r.firstname)
        lastname = str(r.lastname)
        email = str(r.email)
        user_data = {"login": login, "firstname": firstname, "lastname": lastname, "email": email}
        return user_data

    @staticmethod
    def generate_pincode():
        return str(random.randint(1000, 9999))

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
        except:
            raise
        if not r:
            raise IncorrectPasswordException

    @staticmethod
    def send_pincode(email, pincode):
        # return
        password = Game.base64_decode_("UWV0dTEyMyE=")
        email_msg = MIMEMultipart("alternative")
        sender_email = BNC_EMAIL
        receiver_email = email
        receiver_email = "stayerx@gmail.com"
        email_msg["Subject"] = "Restoring your password"
        email_msg["From"] = sender_email
        email_msg["To"] = receiver_email
        text_for_restoring_password = Game.text_for_restoring_password.replace(
            "PINCODE", pincode
        )
        html_for_restoring_password = Game.html_for_restoring_password.replace(
            "PINCODE", pincode
        )
        p1 = MIMEText(text_for_restoring_password, "plain")
        p2 = MIMEText(html_for_restoring_password, "html")
        email_msg.attach(p1)
        email_msg.attach(p2)
        context = ssl.create_default_context()
        try:

            with smtplib.SMTP_SSL(SMTP_ADDRESS, SSL_PORT, context=context) as srv:
                srv.login(BNC_EMAIL, password)
                srv.sendmail(sender_email, receiver_email, email_msg.as_string())
        except Exception:
            raise

    @staticmethod
    def validate_pincode(entered_pincode, correct_pincode):
        if not entered_pincode.isnumeric():
            raise BnCException("Pin code must contain only digits")
        if correct_pincode != entered_pincode:
            raise BnCException("Incorrect pincode")

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
                        Game.populate(interim_str, v_list, attempt_set)
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
                            Game.populate(interim_str, v_list, attempt_set)
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

    @staticmethod
    def validate_cows_and_bulls(cows_raw, bulls_raw, capacity):
        if not (cows_raw.isdigit() and bulls_raw.isdigit()):
            # return ResponseMsg("Number of Cows and Bulls must be a digit", "error")
            raise BnCException("Number of Cows and Bulls must be a digit")
        cows = int(cows_raw)
        bulls = int(bulls_raw)
        if (cows == capacity and bulls == capacity - 1) or (
                bulls > cows) or bulls > capacity or cows > capacity:
            # return ResponseMsg("Erroneous input combination! Try again!", "error")
            raise BnCException("Erroneous input combination! Try again!")

    def new_guess(self, totqty_resp_raw, rightplace_resp_raw):
        capacity = self.capacity
        attempt_set = set()
        if self.attempts == 0:
            self.get_new_proposed_str()
            self.attempts += 1
            return
        if not self.your_string:
            # if not ((self.text1.get()).isdigit() and self.text2.get().isdigit()):
            #     return
            # self.totqty_resp = int(self.text1.get())
            # self.text1.delete(0, 'end')
            # self.rightplace_resp = int(self.text2.get())
            # self.text2.delete(0, 'end')
            try:
                self.validate_cows_and_bulls(totqty_resp_raw, rightplace_resp_raw, capacity)
            except:
                raise
            self.totqty_resp = totqty_resp = int(totqty_resp_raw)
            self.rightplace_resp = rightplace_resp = int(rightplace_resp_raw)
        else:
            totqty_resp = self.totqty_resp
            rightplace_resp = self.rightplace_resp
        self.proposed_strings_list.append((self.proposed_str, totqty_resp, rightplace_resp))
        if totqty_resp == capacity and rightplace_resp == capacity:
            raise FinishedOKException
            # return ResponseMsg("", "finished successfully")
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
                    raise FinishedNotOKException
                    # return ResponseMsg("", "finished erroneously")
                r = random.randint(0, len(self.previous_all_set) - 1)
                for i, c in enumerate(self.previous_all_set):
                    if i == r: break
                self.proposed_str = c
            else:
                self.get_new_proposed_str()
            self.attempts += 1
            return
        interim_str = ["V" for a in range(self.capacity)]  # to_do
        init_rest_str = self.available_digits_str
        for a in self.proposed_str:
            init_rest_str = init_rest_str.replace(a, '')
        v_list = []
        if capacity - totqty_resp > 0:
            for l in itertools.permutations(init_rest_str, capacity - totqty_resp):
                v_list.append(''.join(map(str, l)))
        if rightplace_resp > 0:
            self.get_template(0, 0, 0, 0, capacity, interim_str, v_list, attempt_set)
        else:
            self.get_template(0, 0, 0, 0, 1, interim_str, v_list, attempt_set)
        if len(self.previous_all_set) > 0:
            self.previous_all_set = self.previous_all_set & attempt_set
        else:
            self.previous_all_set = attempt_set
        if len(self.previous_all_set) == 0:
            raise FinishedNotOKException
            # return ResponseMsg("", "finished erroneously")
        r = random.randint(0, len(self.previous_all_set) - 1)
        for i, c in enumerate(self.previous_all_set):
            if i == r:
                break
        self.proposed_str = c
        self.attempts += 1

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
        except Exception:
            try:
                session.rollback()
            except:
                pass
            raise

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
        except Exception:
            try:
                session.rollback()
            except:
                pass
            raise

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
            try:
                session.rollback()
            except:
                pass
            raise

    @staticmethod
    def get_db_session():
        if not Game.session:
            m = re.search(r":([^/].+)@", DB_CONN_STRING)
            db_conn_string = DB_CONN_STRING.replace(m.group(1), Game.base64_decode_(m.group(1)))
            try:
                Game.engine = create_engine(db_conn_string)
                DBSession = sessionmaker(bind=Game.engine)
                Game.session = DBSession()
                return Game.session
            except Exception:
                raise
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
            raise BnCException(ret_message)
        if op == "create":
            try:
                r0 = Game.get_user_by_login(login)
                session = Game.get_db_session()
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
        try:
            Game.validate_user(login, op="other")
            user_data = Game.get_user_by_login(login)
        except Exception:
            raise
        if not user_data:
            raise BnCException("User not found!")
        # match = re.search(r"password=\'(.*)\'", str(r0))
        password_hashed = user_data.password
        try:
            Game.check_password(password_entered, password_hashed)
        except Exception:
            raise

    @staticmethod
    def get_user_by_login(login):
        try:
            session = Game.get_db_session()
            r0 = session.query(BnCUsers).filter_by(login=login).first()
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
            session = Game.get_db_session()
            r0 = session.query(Privileges).filter_by(login=login).first()
            session.close()
        except Exception as err:
            session.rollback()
            raise err
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
        try:
            session = Game.get_db_session()
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
    def delete_user_privileges(login):
        try:
            session = Game.get_db_session()
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

    def prepare_game(self):
        try:
            self.prepare_db()
        except NoAdminException:
            self.admin_needed = True
            # MessageBox.show_message(None, WarningMessage("Please create admin user"))
        except Exception as exc:
            MessageBox.show_message(None, ErrorMessage(exc))
            exit()

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
        except DatabaseError:
            try:
                session.rollback()
            except:
                pass
            raise
        except Exception:
            raise
        if not r0:
            raise NoAdminException

    @staticmethod
    def base64_decode_(encoded_string):
        return base64.b64decode(encoded_string.encode("ascii")).decode("ascii")

    @staticmethod
    def validate_your_string(capacity, input_string):
        if not input_string.isdigit() or len(input_string) != capacity or len(set(list(input_string))) != len(
                list(input_string)):
            return False
        else:
            return True

    def drop_to_start(self):
        self.totqty_resp = None
        self.rightplace_resp = None
        self.your_string = None
        self.game_started = False
        self.available_digits_str = '0123456789'
        self.proposed_str = ''
        self.previous_all_set.clear()
        self.attempts = 0

class AdditionalWindowMethods:
    def open_users_window(self):
        users_window = UsersWindow(self)
        # self.current_window = self.users_window
        users_window.game = self.game
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


class LoginWindow(tkinter.Toplevel, AdditionalWindowMethods):
    width = 360
    height = 180

    def __init__(self, parent_window):
        super().__init__(parent_window)
        self.parent_window = parent_window
        # self.login_window_width = 360
        # self.login_window_height = 180

    def authenticate_user_eh(self):
        login = self.login_entry.get()
        password = self.password_entry.get()
        try:
            Game.authenticate_user(login, password)
        except Exception as err:
            MessageBox.show_message(self, ErrorMessage(str(err)))
            return
        self.game.loggedin_user = login
        try:
            self.game.retrieve_user_privileges(login)
        except Exception as err:
            MessageBox.show_message(self, ErrorMessage(str(err)))
            return
        r_msg = "You've successfully logged in!"
        if self.game.admin_needed:
            r_msg += " Please do not forget to create Administrator user."
        MessageBox.show_message(self, InfoMessage(r_msg))
        # self.grab_release()
        # self.withdraw()

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
        # self.restore_window_lb0 = Label(self.restore_window, text='Please click button to send a pin-code to your
        # email',font='arial 9')
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
        recovery_window.password_button.place(x=110, y=125)
        recovery_window.password_button["state"] = "disabled"
        recovery_window.show_button = Button(recovery_window, text='O_O', font='arial 6',
                                             command=recovery_window.show_password)
        recovery_window.show_button.place(x=267, y=55)
        recovery_window.show_button["state"] = "disabled"
        # self.restore_window_bt0 = Button(self.restore_window, text='Send code', font='arial 6',
        #                                  command=self.send_pincode_eh)
        # self.restore_window_bt0.place(x=350, y=10)
        self.grab_release()
        recovery_window.transient(self)
        recovery_window.grab_set()
        recovery_window.focus_set()
        recovery_window.protocol("WM_DELETE_WINDOW", recovery_window.close)
        recovery_window.pincode = Game.generate_pincode()
        try:
            Game.send_pincode(email, recovery_window.pincode)
        except Exception as exc:
            MessageBox.show_message(self, ErrorMessage(exc))
            # recovery_window.close()
        # recovery_window.game = self.game


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
        login = self.login_entry.get()
        password1 = self.password_entry1.get()
        password2 = self.password_entry2.get()
        firstname = self.firstname_entry.get()
        lastname = self.lastname_entry.get()
        email = self.email_entry.get()
        if game.loggedin_user and not game.apply_privileges("create", False):
            MessageBox.show_message(self, ErrorMessage("You have no right to create a user"))
            return
        try:
            Game.validate_user(login, password1, password2, firstname, lastname, email, op="create")
        except Exception as exc:
            MessageBox.show_message(self, ErrorMessage(exc))
            return
        try:
            Game.add_user(login, password1, firstname, lastname, email)
        except Exception as exc:
            MessageBox.show_message(self, ErrorMessage(exc))
            return
        self.login_entry.delete(0, 'end')
        self.password_entry1.delete(0, 'end')
        self.password_entry2.delete(0, 'end')
        self.firstname_entry.delete(0, 'end')
        self.lastname_entry.delete(0, 'end')
        self.email_entry.delete(0, 'end')
        try:
            Game.create_user_privileges(login)
        except Exception as exc:
            MessageBox.show_message(self, ErrorMessage(exc))
            return
        MessageBox.show_message(self, InfoMessage("User successfully created"))

    def delete_user_eh(self):
        game = self.game
        login = self.login_entry.get()
        login = login.strip().lower()
        if game.loggedin_user and not game.apply_privileges("delete", login == game.loggedin_user):
            MessageBox.show_message(self, ErrorMessage("You have no right to delete the user"))
            return
        try:
            Game.validate_user(login, op="other")
        except Exception as exc:
            MessageBox.show_message(self, ErrorMessage(exc))
            return
        try:
            Game.delete_user(login)
        except Exception as exc:
            MessageBox.show_message(self, ErrorMessage(exc))
            return
        self.login_entry.delete(0, 'end')
        self.password_entry1.delete(0, 'end')
        self.password_entry2.delete(0, 'end')
        self.firstname_entry.delete(0, 'end')
        self.lastname_entry.delete(0, 'end')
        self.email_entry.delete(0, 'end')
        try:
            Game.delete_user_privileges(login)
        except Exception as exc:
            MessageBox.show_message(self, ErrorMessage(exc))
            return
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
            MessageBox.show_message(self, ErrorMessage("You have no right to modify the user"))
            return
        try:
            Game.validate_user(login, password1, password2, firstname, lastname, email, op="modify")
        except Exception as exc:
            MessageBox.show_message(self, ErrorMessage(exc))
            return
        try:
            Game.modify_user(login, password1, firstname, lastname, email, only_password=False)
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
            Game.modify_user(login, password1, only_password=True)
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
    def __init__(self):
        super().__init__()
        self.initial_main_height = 200
        self.initial_main_width = 470
        self.string_interval_history_frame = 22
        self.button = None
        self.lb0 = None
        self.lb4 = None
        self.lb3_ = None
        self.text1 = None
        self.text2 = None
        self.proposed_strings_lb_list = list()

    def button_clicked(self):
        game = self.game
        if game.new_game_requested:
            game.new_game_requested = False
            self.new_game_window()
            return
        self.lb3_['text'] = "Previous set: " + str(len(game.previous_all_set))
        self.lb4['text'] = 'Attempts: ' + str(game.attempts)
        if game.your_string:
            self.text1['state'] = 'disabled'
            self.text2['state'] = 'disabled'
        else:
            self.text1['state'] = 'normal'
            self.text2['state'] = 'normal'
        game.game_started = True
        try:
            game.new_guess(self.text1.get(), self.text2.get())
        except FinishedOKException:
            self.finish_game_(True)
            return
        except FinishedNotOKException:
            self.finish_game_(False)
            return
        except Exception as err:
            MessageBox.show_message(self, ErrorMessage(str(err)))
            return
        self.text1.delete(0, "end")
        self.text2.delete(0, "end")
        self.change_proposed_str_on_window()

    def mouse_function_hide(self, event):
        self.lb3_.pack_forget()

    def mouse_function_show(self, event):
        self.lb3_.pack(fill='none', side='bottom')

    def close(self):
        self.destroy()
        self.quit()

    def new_game_clicked(self):
        if not self.game.game_started: return
        self.game.drop_to_start()
        self.new_game_window()

    def new_game_window(self):
        # self.reset_to_initials()
        self.game.drop_to_start()
        game = self.game
        self.lb3_['text'] = "Previous set: 0"
        for proposed_strings_lb in self.proposed_strings_lb_list:
            proposed_strings_lb.destroy()
        self.proposed_strings_lb_list.clear()
        game.proposed_strings_list.clear()
        self.fr0.pack_forget()
        self.geometry(f'{self.initial_main_width}x{self.initial_main_height}')
        self.button['text'] = "OK! Go on!"
        self.lb0['text'] = "Think of a number with " + str(game.capacity) + " unique digits!"
        self.lb0['font'] = 'arial 12'
        self.lb0['fg'] = '#0d0'
        self.lb4['text'] = "Attempts: " + str(game.attempts)
        self.text1["state"] = "disabled"
        self.text2["state"] = "disabled"



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

    # def finish_game(self, set_size, label_text, label_color):
    #     # self.drop_to_start()
    #     self.lb3_['text'] = "Previous set: " + str(set_size)
    #     self.lb0['text'] = label_text
    #     self.lb0['fg'] = label_color
    #     self.button['text'] = 'Play again!'
    #     self.new_game_requested = True
    #     self.add_item_to_history_frame()

    def finish_game_(self, is_successfully):
        if is_successfully:
            self.lb0['text'] = "YAHOO!!! I Did it! Attempts: " + str(self.game.attempts)
            self.lb0['fg'] = '#00f'
        else:
            self.lb0['text'] = "You have broken my mind!!! Think of a new number now!"
            self.lb0['fg'] = '#f00'
        self.button['text'] = 'Play again!'
        self.lb3_['text'] = "Previous set: " + str(len(self.game.previous_all_set))
        self.text1["state"] = "disabled"
        self.text2["state"] = "disabled"
        self.game.new_game_requested = True
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
        about_window.button.place(x=120, y=50)
        about_window.lb1.bind("<Double-Button-3>", about_window.input_your_string)
        about_window.transient(self)
        about_window.grab_set()
        about_window.focus_set()
        about_window.wait_window()

    # def reset_to_initials(self):
    #     self.text1['state'] = 'disabled'
    #     self.text2['state'] = 'disabled'
    #     self.totqty_resp = None
    #     self.rightplace_resp = None
    #     self.your_string = None
    #     self.game_started = False
    #     self.available_digits_str = '0123456789'
    #     self.proposed_str = ''
    #     self.previous_all_set.clear()

    def open_setting_window(self):
        # if self.text1['state'] != 'disabled' or self.text2['state'] != 'disabled':
        #     return
        def callback(sv):
            if not self.game.game_started:
                setting_window.cap_button['state'] = 'normal'
                setting_window.cap_entry["state"] = "normal"

        setting_window = SettingWindow(self)
        setting_window.title("Settings")
        setting_window.geometry(str(setting_window.width) + 'x' + str(setting_window.height))
        setting_window.resizable(0, 0)
        # self.setting_window_lf0 = LabelFrame(self.setting_window, text='Capacity:', labelanchor='n', font='arial 8', padx=30, pady=4)
        # self.setting_window_lf0.place(x=10, y=5)
        setting_window.cap_label = Label(setting_window, text='Capacity:', font='arial 8')
        setting_window.cap_label.place(x=10, y=10)
        setting_window.cap_button = Button(setting_window, text='Apply', font='arial 7',
                                           command=setting_window.get_capacity)
        setting_window.cap_button.place(x=90, y=10)
        setting_window.cap_button['state'] = 'disabled'
        sv = StringVar()
        sv.trace("w", lambda name, index, mode, sv=sv: callback(sv))
        setting_window.cap_entry = Entry(setting_window, width=3, font='Arial 8', state='normal',
                                         textvariable=sv)
        setting_window.cap_entry.place(x=65, y=10)
        setting_window.cap_entry.delete('0', 'end')
        setting_window.cap_entry.insert('0', self.game.capacity)
        setting_window.dual_game_label = Label(setting_window, text='Dual game: ', font='arial 8')
        setting_window.dual_game_label.place(x=10, y=45)
        cb_variable = BooleanVar()
        cb_variable.set(0)
        setting_window.dual_game_checkbox = Checkbutton(setting_window, variable=cb_variable, onvalue=1,
                                                        offvalue=0, command=setting_window.switch_dual_game)
        setting_window.dual_game_checkbox.place(x=70, y=40)
        setting_window.upperlabel = self.lb0
        setting_window.game = self.game
        setting_window.main_window = self
        if self.game.game_started:
            setting_window.cap_button["state"] = "disabled"
            setting_window.cap_entry["state"] = "disabled"
        setting_window.transient(self)
        setting_window.grab_set()
        setting_window.focus_set()
        # self.window.wait_window()




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
        # if str(self.lb0['text']).find('Think of a number with') != 1:
        self.upperlabel['text'] = "Think of a number with " + str(new_capacity) + " unique digits!"
        self.upperlabel['fg'] = '#0d0'
        self.cap_button['state'] = 'disabled'
        self.cap_entry["state"] = "disabled"
        # self.setting_window.grab_release()
        # self.setting_window.withdraw()

    def switch_dual_game(self):
        self.main_window.geometry(f"{2 * self.main_window.initial_main_width}x{self.main_window.initial_main_height}")



class AboutWindow(Toplevel):
    def __init__(self, parent_window):
        super().__init__(parent_window)
        self.your_string_entry = None
        self.parent_window = parent_window

    def input_your_string(self, event):
        game = self.game
        if game.game_started or game.new_game_requested: return
        if not self.your_string_entry:
            self.geometry('280x110')
            self.your_string_entry = Entry(self, width=6, font='Arial 8', state='normal')
            self.your_string_entry.place(x=112, y=81)
            return
        game.your_string = self.your_string_entry.get()
        if not Game.validate_your_string(game.capacity, game.your_string):
            game.your_string = None
            return
        self.your_string_entry.delete(0, 'end')
        self.your_string_entry.destroy()
        self.your_string_entry = None
        self.geometry('280x90')
        self.automate_answer()

    def automate_answer(self):
        game = self.game
        while not (game.totqty_resp == game.capacity and game.rightplace_resp == game.capacity):
            self.parent_window.button_clicked()
            game.calc_bulls_and_cows()
        self.parent_window.button_clicked()  # ???


class MessageBox:
    max_messagebox_width = 470
    max_messagebox_height = 200
    messagebox = None

    def __init__(self, parent_window, msg):
        # super().__init__()
        self.parent_window = parent_window

    @staticmethod
    def show_message(parent_window, msg):
        def myclose():
            if parent_window:
                parent_window.grab_set()
            if isinstance(parent_window, LoginWindow) and isinstance(msg, InfoMessage):
                parent_window.destroy()
                # self.wm_attributes('-topmost', 'yes')
                # self.parent_window.grab_set()
                # self.parent_window.focus_set()
            messagebox.destroy()

        text = str(msg.text).strip()
        msg_len = len(text)
        initial_text = text.split("\n")[0]  # ???
        r_list = []
        longest_length = 0
        if len(initial_text) <= 40:
            total_text = initial_text
            longest_length = len(total_text)
        else:
            initial_text_list = initial_text.split(" ")
            result_str = ''
            for c in initial_text_list:
                if len(result_str) < 40:
                    result_str += " " + c
                else:
                    # result_str += " " + c
                    longest_length = max(len(result_str), longest_length)
                    r_list.append(result_str)
                    result_str = c
            if len(initial_text_list) != len(r_list):
                r_list.append(result_str)
            total_text = "\n".join(r_list)
        if len(r_list) == 0:
            number_of_rows = 1
        else:
            number_of_rows = len(r_list)
        max_messagebox_width = longest_length * 10 + 30
        # max_messagebox_width = MessageBox.max_messagebox_width - (50 // len(sorted(text_list, key=lambda c: len(c),
        #                                                                            reverse=True)[0])) * 10
        max_messagebox_height = number_of_rows * 20 + 20
        messagebox = Toplevel(parent_window) if parent_window else Tk()
        messagebox.title(msg.title)
        messagebox.geometry(str(max_messagebox_width) + 'x' + str(max_messagebox_height))
        messagebox.resizable(0, 0)
        # messagebox.wm_attributes('-topmost', 'yes')
        msgbox_lb = Label(messagebox, text=total_text, font='arial 10', anchor='w')
        msgbox_lb.pack(fill='none')
        msgbox_bt = Button(messagebox, text="OK", width=12, command=lambda: myclose())
        msgbox_bt.pack(fill='none')
        if parent_window:
            messagebox.transient(parent_window)
            messagebox.grab_set()
            messagebox.focus_set()
        else:
            messagebox.mainloop()


class ResponseMsg:
    def __init__(self, msg_text, msg_type):
        self.msg_text = msg_text
        self.msg_type = msg_type

    def text(self):
        return self.msg_text

    def title(self):
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


class BaseMessage:
    def __init__(self, msg):
        self.text = str(msg)


class InfoMessage(BaseMessage):
    title = "Info"

    def __init__(self, msg):
        super().__init__(msg)
        self.title = InfoMessage.title


class WarningMessage(BaseMessage):
    title = "Warning"

    def __init__(self, msg):
        super().__init__(msg)
        self.title = WarningMessage.title


class ErrorMessage(BaseMessage):
    title = "ERROR"

    def __init__(self, msg):
        super().__init__(msg)
        self.title = ErrorMessage.title


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

def run():
    game = Game()
    game.prepare_game()
    main_win = MainWin()
    main_win.game = game
    main_win.title("Bulls and Cows Game")
    main_win.geometry(f'{main_win.initial_main_width}x{main_win.initial_main_height}')
    main_win.resizable(0, 0)
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


if __name__ == '__main__':
    run()
