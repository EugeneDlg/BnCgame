import base64
import random
import re
import tkinter
from tkinter import *
from itertools import permutations
from secrets import choice
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
    good_mood_phrases = [
        "Wishing you and me an interesting game!",
        "Hope you will win!:) (Actually not, ha-ha)",
        "Best luck for your playing! I believe in you!:)",
        "May God bless you with boundless success!",
        "Stop worrying and start doing!",
        "I know nothing can make you down. Nothing can damage your confidence!",
        "Stop masturbating and play carefully!",
        "Put your best efforts and earn your success!",
        "Great accomplishments and success are my best wishes for you today!",
        "My good wishes will always be with you. Best of luck!",
        "I am not a bit worried about your win. As I believe in you!"
        "Ace it.",
        "Sending you abundant wishes for this game!",
        "Failure and success are the two sides of the same coin. So don’t get nervous!"
    ]

    def __init__(self, capacity=4):
        super().__init__()
        self.capacity = capacity
        self.my_history_list = list()
        self.your_history_list = list()
        self.previous_all_set = set()
        self.new_game_requested = False
        self.loggedin_user = None
        self.admin_needed = False
        self.dual_game_enabled = True
        self.user_privileges = None
        self.game_initials()

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

    @staticmethod
    def calc_bulls_and_cows(true_number, guess_number):
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
            # return ResponseMsg("Number of Cows and Bulls must be a digit", "error")
            raise BnCException("Number of Cows and Bulls must be a digit")
        cows = int(cows_raw)
        bulls = int(bulls_raw)
        if (cows == capacity and bulls == capacity - 1) or (
                bulls > cows) or bulls > capacity or cows > capacity:
            # return ResponseMsg("Erroneous input combination! Try again!", "error")
            raise BnCException("Erroneous input combination! Try again!")

    def my_guess(self, totqty_resp_raw, rightplace_resp_raw):
        capacity = self.capacity
        attempt_set = set()

        if not self.your_string_for_automation_mono_game:
            # if not ((self.text1.get()).isdigit() and self.text2.get().isdigit()):
            #     return
            # self.totqty_resp = int(self.text1.get())
            # self.text1.delete(0, 'end')
            # self.rightplace_resp = int(self.text2.get())
            # self.text2.delete(0, 'end')

            self.totqty_resp = totqty_resp = int(totqty_resp_raw)
            self.rightplace_resp = rightplace_resp = int(rightplace_resp_raw)
        else:
            totqty_resp = self.totqty_resp
            rightplace_resp = self.rightplace_resp
        self.my_history_list.append((self.proposed_str, totqty_resp, rightplace_resp))
        if totqty_resp == capacity and rightplace_resp == capacity:
            # raise FinishedOKException
            return True
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
            return False
        interim_str = ["V" for a in range(self.capacity)]  # to_do
        init_rest_str = self.available_digits_str
        for a in self.proposed_str:
            init_rest_str = init_rest_str.replace(a, '')
        v_list = []
        if capacity - totqty_resp > 0:
            for l in permutations(init_rest_str, capacity - totqty_resp):
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
        return False

    def your_guess(self, your_guess_string):
        if self.attempts < 1:
            return False
        self.your_cows, self.your_bulls = self.calc_bulls_and_cows(self.my_string_for_you, your_guess_string)
        self.your_history_list.append((your_guess_string, self.your_cows, self.your_bulls))
        if self.your_cows==self.capacity and self.your_bulls==self.capacity:
            return True
        else:
            return False

    def think_of_number_for_you(self):
        self.my_string_for_you = "".join(choice(list(permutations("0123456789", self.capacity))))

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
            raise BnCException("You entered an invalid string trying to guess my number!")

    def game_initials(self):
        self.previous_all_set.clear()
        self.my_history_list.clear()
        self.your_history_list.clear()
        self.totqty_resp = None
        self.rightplace_resp = None
        self.your_string_for_automation_mono_game = None
        self.my_string_for_you = None
        self.your_cows = None
        self.your_bulls = None
        self.available_digits_str = '0123456789'
        self.proposed_str = ''
        self.attempts = 0
        self.game_started = False

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
        self.mono_game_main_height = 200
        self.mono_game_main_width = 400
        self.dual_game_main_height = self.mono_game_main_height + 100
        self.dual_game_main_width = int(1.4 * self.mono_game_main_width)
        self.string_interval_history_frame = 22
        self.windows_initials()

    def windows_initials(self):
        self.go_button = None
        self.upper_label = None
        self.attempts_label = None
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

    def go_button_clicked(self):
        game = self.game
        if game.new_game_requested:
            game.new_game_requested = False
            self.new_game_window()
            return
        # self.lb3_['text'] = "Previous set: " + str(len(game.previous_all_set))
        self.attempts_label['text'] = 'Attempts: ' + str(game.attempts)
        if not game.your_string_for_automation_mono_game:
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
        game.game_started = True
        if game.attempts == 0:
            game.get_new_proposed_str()
            game.think_of_number_for_you()
            game.attempts += 1
            if game.dual_game_enabled:
                self.change_data_on_window_dual_game()
            else:
                self.change_data_on_window_mono_game()
            return
        my_cows_entered = self.my_cows_entry.get().strip()
        my_bulls_entered = self.my_bulls_entry.get().strip()
        try:
            game.validate_cows_and_bulls(my_cows_entered, my_bulls_entered, game.capacity)
            if game.dual_game_enabled and game.attempts > 0:
                your_guess_entered = self.your_guess_entry.get().strip()
                game.validate_your_string(game.capacity, your_guess_entered)
                your_result = game.your_guess(your_guess_entered)
            else:
                your_result = False
            my_result = game.my_guess(my_cows_entered, my_bulls_entered)
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

    def mouse_function_hide(self, event):
        self.lb3_.pack_forget()

    def mouse_function_show(self, event):
        self.lb3_.pack(fill='none', side='bottom')

    def close(self):
        self.destroy()
        self.quit()


    def new_game_clicked(self):
        if not self.game.game_started: return
        self.game.game_initials()
        self.new_game_window()

    def new_game_window(self):
        # self.reset_to_initials()
        game = self.game
        game.game_initials()
        # self.my_history_frame = LabelFrame(self, text='History of attempts', labelanchor='n', font='arial 8',
        #                                    padx='80')
        # self.geometry(f'{self.initial_main_width}x{self.initial_main_height}')
        # self.go_button['text'] = "OK! Go on!"
        # self.upper_label['font'] = 'arial 12'
        # self.upper_label['fg'] = '#0d0'
        # self.attempts_label['text'] = "Attempts: " + str(game.attempts)
        # self.my_cows_entry.delete(0, "end")
        # self.my_bulls_entry.delete(0, "end")
        # self.my_cows_entry["state"] = "disabled"
        # self.my_bulls_entry["state"] = "disabled"
        # self.upper_label['text'] = "Think of a number with " + str(game.capacity) + " unique digits!" #???
        if game.dual_game_enabled:
            self.enable_dual_game()
        else:
            self.enable_mono_game()
        game.think_of_number_for_you() #???

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
    #     # self.game_initials()
    #     self.lb3_['text'] = "Previous set: " + str(set_size)
    #     self.lb0['text'] = label_text
    #     self.lb0['fg'] = label_color
    #     self.button['text'] = 'Play again!'
    #     self.new_game_requested = True
    #     self.add_item_to_my_history_frame()

    def finish_game_on_main_window(self, game_result_code):
        if game_result_code == 0:   ####
            self.upper_label['text'] = "You have broken my mind! Please be more concentrated!\nThink of a new number!"
            self.upper_label['fg'] = '#f00'
        elif game_result_code == 1:
            self.upper_label['text'] = "YAHOO! I've won! Thank you for interesting play!\n" \
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
        #self.lb3_['text'] = "Previous set: " + str(len(self.game.previous_all_set))
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
        self.game.new_game_requested = True
        if self.game.dual_game_enabled:
            self.add_item_to_my_and_your_history_frame()
        else:
            self.add_item_to_my_history_frame()

    def change_data_on_window_mono_game(self):
        self.my_cows_entry.delete(0, "end")
        self.my_bulls_entry.delete(0, "end")
        self.upper_label['text'] = 'I guess your number is : "' + self.game.proposed_str
        self.upper_label['fg'] = '#000'
        self.go_button["text"] = "OK!"
        self.attempts_label['text'] = 'Attempts: ' + str(self.game.attempts)
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
        my_frame_lb = Label(self.my_history_frame, text=str(t0[0]) + "  " + str(t0[1]) + "." + str(t0[2]), font='arial 9')
        my_frame_lb.pack()
        self.my_history_lb_list.append(my_frame_lb)

    def change_data_on_window_dual_game(self):
        self.upper_label["text"] = choice(Game.good_mood_phrases)
        self.my_cows_entry.delete(0, "end")
        self.my_bulls_entry.delete(0, "end")
        self.your_guess_entry.delete(0, "end")
        self.my_upper_label['text'] = 'I guess your number is : "' + self.game.proposed_str
        self.upper_label['fg'] = '#000'
        self.attempts_label['text'] = 'Attempts: ' + str(self.game.attempts)
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
        self.go_button.place(x=int(1.4*self.initial_main_width/2-200),
                             y=240+self.string_interval_history_frame*(len(game.my_history_list)-1))



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
        about_window.lb1.bind("<Double-Button-3>", about_window.input_your_string_for_automation_mono_game)
        about_window.button.bind("<Double-Button-3>", about_window.show_my_guessed_number)
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
        setting_window.game = self.game
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
        setting_window.cb_variable = BooleanVar()
        setting_window.cb_variable.set(int(self.game.dual_game_enabled))
        setting_window.dual_game_checkbox = Checkbutton(setting_window, variable=setting_window.cb_variable,
                                                        onvalue=1, offvalue=0,
                                                        command=setting_window.switch_dual_game)
        setting_window.dual_game_checkbox.place(x=70, y=40)
        setting_window.dual_game_checkbox.select() if self.game.dual_game_enabled else \
            setting_window.dual_game_checkbox.deselect()
        setting_window.upperlabel = self.upper_label
        setting_window.main_window = self
        if self.game.game_started:
            setting_window.cap_button["state"] = "disabled"
            setting_window.cap_entry["state"] = "disabled"
        setting_window.transient(self)
        setting_window.grab_set()
        setting_window.focus_set()
        # self.window.wait_window()

    def enable_mono_game(self):
        game = self.game
        self.destroy_previous_window_items()
        self.windows_initials()
        self.initial_main_width = self.mono_game_main_width
        self.initial_main_height = self.mono_game_main_height
        self.geometry(f'{self.initial_main_width}x{self.initial_main_height}')
        self.resizable(0, 0)
        self.upper_label = Label(self, text="Think of a number with " + str(game.capacity) + " unique digits!",
                                     font='arial 12')
        self.upper_label.bind("<Double-Button-1>", self.mouse_function_hide)
        self.upper_label.bind("<Double-Button-3>", self.mouse_function_show)
        self.upper_label['fg'] = '#0d0'
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
        self.lb3_ = Label(self, text="Previous set: " + str(len(game.previous_all_set)), font='arial 5')
        #  lb3_.pack(fill='none', side='bottom')
        #  lb3_.pack_forget()
        self.attempts_label = Label(self, text="Attempts: " + str(game.attempts), font='arial 8')
        self.attempts_label.pack(side="bottom")

    def enable_dual_game(self):
        game = self.game
        self.destroy_previous_window_items()
        self.windows_initials()
        self.initial_main_width = self.dual_game_main_width
        self.initial_main_height = self.dual_game_main_height
        self.geometry(f'{self.initial_main_width}x{self.initial_main_height}')
        self.resizable(0, 0)
        self.upper_label = Label(self, text="Think of a number with " + str(game.capacity) + " unique digits!\n"
                                 "And I will think of a number to guess for you!",
                                     font='arial 12')
        self.upper_label.bind("<Double-Button-1>", self.mouse_function_hide)
        self.upper_label.bind("<Double-Button-3>", self.mouse_function_show)
        self.upper_label['fg'] = '#0d0'
        # self.upper_label.place(x=70, y=5)
        self.upper_label.pack()
        self.my_outer_frame = LabelFrame(self, text='My part', labelanchor='n', font='arial 8', padx='40', pady='5')
        self.my_outer_frame.place(x=15, y=50)
        self.my_upper_label = Label(self.my_outer_frame, text="I guess your number is: "+ "    ", font='arial 11')
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
        self.my_align_label = Label(self.my_outer_frame, text="\n", font='arial 4')
        self.my_align_label.pack()
        self.my_history_frame = LabelFrame(self.my_outer_frame, text='History of attempts', labelanchor='n', font='arial 8', padx='40')
        self.my_history_frame.pack()
        # self.lb002 = Label(self.my_history_frame, text="1111 1.1", font='arial 9')
        # self.lb002.pack()
        self.your_outer_frame = LabelFrame(self, text='Your part', labelanchor='n', font='arial 8', padx='60', pady='3')
        self.your_outer_frame.place(x=280, y=50)
        self.your_upper_label = Label(self.your_outer_frame, text="Enter your guess: ", font='arial 11')
        self.your_upper_label.pack()
        self.your_upper_label["state"] = "disabled"
        self.your_guess_entry = Entry(self.your_outer_frame, width=game.capacity+2, font='Arial 11', state='disabled')
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
        self.your_history_frame = LabelFrame(self.your_outer_frame, text='History of attempts', labelanchor='n', font='arial 8', padx='40')
        self.your_history_frame.pack()
        # self.lb001 = Label(self.your_history_frame, text="1111 1.1", font='arial 9')
        # self.lb001.pack()
        self.go_button = Button(self, text="OK! Go on!", width=20, command=self.go_button_clicked)
        self.go_button.place(x=int(1.4*self.initial_main_width/2-200), y=230)
        #self.go_button.pack(side="bottom")
        self.attempts_label = Label(self, text="Attempts: " + str(game.attempts), font='arial 10')
        self.attempts_label.pack(side="bottom")

    def destroy_previous_window_items(self):
        if self.my_outer_frame:
            self.my_outer_frame.destroy()
        if self.your_outer_frame:
            self.your_outer_frame.destroy()
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
        if self.lb3_:
            self.lb3_.destroy()

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
        self.game.dual_game_enabled = bool(self.cb_variable.get())
        if self.game.dual_game_enabled:
            self.main_window.enable_dual_game()
        else:
            self.main_window.enable_mono_game()
        # self.main_window.geometry(f"{2 * self.main_window.initial_main_width}x{self.main_window.initial_main_height}")



class AboutWindow(Toplevel):
    def __init__(self, parent_window):
        super().__init__(parent_window)
        self.your_string_entry = None
        self.parent_window = parent_window

    def input_your_string_for_automation_mono_game(self, event):
        game = self.game
        if game.game_started or game.new_game_requested or game.dual_game_enabled: return
        if not self.your_string_entry:
            self.geometry('280x110')
            self.your_string_entry = Entry(self, width=game.capacity+2, font='Arial 8', state='normal')
            self.your_string_entry.place(x=112, y=81)
            return
        your_string = strip(self.your_string_entry.get())
        if not Game.validate_your_string(game.capacity, your_string):
            game.your_string_for_automation_mono_game = None
            return
        else:
            game.your_string_for_automation_mono_game = your_string
        self.your_string_entry.delete(0, 'end')
        self.your_string_entry.destroy()
        self.your_string_entry = None
        self.geometry('280x90')
        self.automate_answer()

    def automate_answer(self):
        game = self.game
        while not (game.totqty_resp == game.capacity and game.rightplace_resp == game.capacity):
            self.parent_window.go_button_clicked()
            game.totqty_resp, game.rightplace_resp = game.calc_bulls_and_cows(
                game.your_string_for_automation_mono_game, game.proposed_str)
        self.parent_window.go_button_clicked()  # ???

    def show_my_guessed_number(self, event):
        self.button["text"] = self.game.my_string_for_you

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
    if game.dual_game_enabled :
        main_win.enable_dual_game()
    else:
        main_win.enable_mono_game()
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

    main_win.protocol('WM_DELETE_WINDOW', main_win.close)
    # main_win.open_login_window()
    main_win.mainloop()


if __name__ == '__main__':
    run()
