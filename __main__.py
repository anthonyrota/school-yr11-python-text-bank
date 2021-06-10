from enum import Enum, auto
from platform import system
from uuid import uuid4
from datetime import datetime
from tendo.singleton import SingleInstance, logger as singletonLogger
import tableprint as tp
import os
import pathlib
import hashlib
import hmac
import json
import base64
import re
import sys

from prompt_toolkit import HTML
from prompt_toolkit.styles import Style
from prompt_toolkit.layout.controls import FormattedTextControl
from prompt_toolkit.filters import renderer_height_is_known, has_focus
from button_replacement import Button
from prompt_toolkit.widgets import (
    Dialog,
    Label,
    TextArea,
    Box,
    Frame,
    RadioList,
    CheckboxList
)
from prompt_toolkit.layout.dimension import Dimension
from prompt_toolkit.layout.containers import (
    Window,
    ConditionalContainer,
    DynamicContainer,
    VSplit,
    HSplit,
    WindowAlign,
    HorizontalAlign,
    VerticalAlign
)
from prompt_toolkit.layout import Layout
from prompt_toolkit.key_binding.key_bindings import KeyBindings, merge_key_bindings
from prompt_toolkit.key_binding.bindings.focus import focus_next, focus_previous
from prompt_toolkit.output.color_depth import ColorDepth
from prompt_toolkit.application.current import get_app
from prompt_toolkit.application import Application


singletonLogger.disabled = True
try:
    # https://tendo.readthedocs.io/en/latest/#module-tendo.singleton
    me = SingleInstance()
except:
    sys.exit("ATM is already running...")


# The target element to focus when switching scenes. if none, equals None.
# this is safe because only one app can run at a time.
global__default_target_focus = None


def exit_current_app():
    """Exits the current application, restoring previous terminal state."""
    get_app().exit()


class RootScreenType(Enum):
    LOGIN = auto()
    SIGN_UP = auto()
    MENU = auto()
    DEPOSIT = auto()
    WITHDRAW = auto()
    ACCOUNT = auto()
    TRANSACTIONS = auto()
    CHANGE_USERNAME = auto()
    CHANGE_NAME = auto()
    CHANGE_PIN = auto()
    DELETE_ACCOUNT_1 = auto()
    DELETE_ACCOUNT_2 = auto()


class ScreenState:
    def __init__(self, session):
        self.session = session


class LoginScreenState(ScreenState):
    """Initial screen where user logs in using their credentials. Users can also
    sign up to create a new account. After entering the form the user is taken to
    the menu screen."""
    root_screen_type = RootScreenType.LOGIN


class SignUpScreenState(ScreenState):
    root_screen_type = RootScreenType.SIGN_UP


class MenuScreenState(ScreenState):
    """Screen where user can navigate to all the other screens/use ATM's functions"""
    root_screen_type = RootScreenType.MENU


class DepositScreenState(ScreenState):
    root_screen_type = RootScreenType.DEPOSIT


class WithdrawScreenState(ScreenState):
    root_screen_type = RootScreenType.WITHDRAW


class AccountScreenState(ScreenState):
    root_screen_type = RootScreenType.ACCOUNT


class TransactionsScreenFilter(Enum):
    DEPOSIT_ONLY = auto()
    WITHDRAW_ONLY = auto()
    BOTH = auto()


class TransactionsScreenState(ScreenState):
    root_screen_type = RootScreenType.TRANSACTIONS

    def __init__(self, session, filter):
        super().__init__(session)
        self.filter = filter


class ChangeUsernameScreenState(ScreenState):
    root_screen_type = RootScreenType.CHANGE_USERNAME


class ChangeNameScreenState(ScreenState):
    root_screen_type = RootScreenType.CHANGE_NAME


class ChangePinScreenState(ScreenState):
    root_screen_type = RootScreenType.CHANGE_PIN


class DeleteAccount1ScreenState(ScreenState):
    root_screen_type = RootScreenType.DELETE_ACCOUNT_1


class DeleteAccount2ScreenState(ScreenState):
    root_screen_type = RootScreenType.DELETE_ACCOUNT_2


class Session:
    def __init__(self, db, account_id=None):
        self.db = db
        self.account_id = account_id


def table_to_txt(table):
    def add_row_separator(ch):
        nonlocal txt
        for size in col_max_lens:
            txt += '+'
            txt += ch * (size + 2)
        txt += '+'
    txt = ''
    col_max_lens = [0] * len(table[0])
    for row in table:
        for i, cell in enumerate(row):
            col_max_lens[i] = max(col_max_lens[i], len(cell))
    add_row_separator('-')
    txt += '\n'
    for i, row in enumerate(table):
        for j, cell in enumerate(row):
            txt += '| '
            if i == 0:
                txt += cell.center(col_max_lens[j])
            else:
                txt += cell.ljust(col_max_lens[j])
            txt += ' '
        txt += '|\n'
        if i == 0:
            add_row_separator('=')
        else:
            add_row_separator('-')
        if i != len(table) - 1:
            txt += '\n'
    return txt


def encode_bytes(b):
    return base64.b64encode(b).decode('ascii')


def decode_bytes(b):
    return base64.b64decode(b)


def format_balance(balance):
    balance_str = str(balance).zfill(3)
    dollars = balance_str[:-2]
    cents = balance_str[-2:]
    return f'${dollars}.{cents}'


def delete_folder(pth):
    p = pathlib.Path(pth)
    # https://stackoverflow.com/questions/303200/how-do-i-remove-delete-a-folder-that-is-not-empty
    for sub in p.iterdir():
        if sub.is_dir():
            delete_folder(sub)
        else:
            sub.unlink()
    p.rmdir()


class TransactionType(Enum):
    DEPOSIT = 'd'
    WITHDRAW = 'w'


class DB:
    def __init__(self, data, insecure_txt_db):
        self._data = data
        self._insecure_text_db = insecure_txt_db

    def get_account_from_account_id(self, account_id):
        account = self._data['accounts'][account_id]
        return {
            "account_id": account_id,
            "username": account['username'],
            "name": account['name'],
            "pin": {
                "salt": decode_bytes(account['pin'][0]),
                "pw_hash": decode_bytes(account['pin'][1])
            },
            "balance": int(account['balance']),
            "transactions": [{
                "type": TransactionType(transaction["type"]),
                "value": transaction["value"],
                "timestamp": datetime.fromtimestamp(transaction["timestamp"])
            } for transaction in account['transactions']],
            "created_at": datetime.fromtimestamp(account['created_at'])
        }

    def get_account_from_username(self, username):
        account_username_to_account_id = self._data['account_username_to_account_id']
        if username not in account_username_to_account_id:
            return None
        account_id = account_username_to_account_id[username]
        return self.get_account_from_account_id(account_id)

    def make_account_with_details(self, username, name, pin):
        account_id = str(uuid4())
        salt, pw_hash = hash_new_password(pin)
        self._data['accounts'][account_id] = {
            'username': username,
            'name': name,
            'pin': [encode_bytes(salt), encode_bytes(pw_hash)],
            'balance': 0,
            'transactions': [],
            'created_at': datetime.now().timestamp()
        }
        self._data['account_username_to_account_id'][username] = account_id
        self._insecure_text_db[account_id] = pin
        save_db(self)
        os.mkdir(f'receipts/{username}')
        return account_id

    def change_account_username(self, account_id, new_username):
        old_username = self._data['accounts'][account_id]['username']
        self._data['accounts'][account_id]['username'] = new_username
        self._data['account_username_to_account_id'].pop(old_username)
        self._data['account_username_to_account_id'][new_username] = account_id
        save_db(self)
        os.rename(f'receipts/{old_username}', f'receipts/{new_username}')

    def change_account_name(self, account_id, new_name):
        self._data['accounts'][account_id]['name'] = new_name
        save_db(self)

    def change_account_pin(self, account_id, new_pin):
        salt, pw_hash = hash_new_password(new_pin)
        self._data['accounts'][account_id]['pin'] = [
            encode_bytes(salt), encode_bytes(pw_hash)]
        self._insecure_text_db[account_id] = new_pin
        save_db(self)

    def delete_account(self, account_id):
        username = self._data['accounts'][account_id]['username']
        self._data['accounts'].pop(account_id)
        self._data['account_username_to_account_id'].pop(username)
        self._insecure_text_db.pop(account_id)
        save_db(self)
        delete_folder(f'receipts/{username}')

    def set_account_balance(self, account_id, new_balance):
        self._data['accounts'][account_id]['balance'] = new_balance
        save_db(self)

    def record_account_transaction(self, account_id, type, value):
        date = datetime.now()
        timestamp = date.timestamp()
        self._data['accounts'][account_id]['transactions'].append({
            'type': type.value,
            'value': value,
            'timestamp': timestamp
        })
        save_db(self)
        t = TablePrintOut()
        tp.table([
            ["DATE", date.strftime("%d/%m/%Y")],
            ["TIME", date.strftime("%I:%M %p")],
            ["TRANSACTION", "DEPOSIT" if type ==
                TransactionType.DEPOSIT else "WITHDRAWAL"],
        ], style="block", out=t)
        receipt_info_table_txt = t.txt
        t = TablePrintOut()
        account = self.get_account_from_account_id(account_id)
        tp.table([
            [f"{'DEPOSITED' if type == TransactionType.DEPOSIT else 'DISPENSED'} AMOUNT",
                format_balance(value)],
            [f"ACCOUNT BALANCE", format_balance(account["balance"])]
        ], style="block", out=t)
        receipt_numbers_table_txt = t.txt
        receipt_txt = '\n'.join([
            "SMH BANK",
            "",
            receipt_info_table_txt,
            account['name'],
            receipt_numbers_table_txt,
            "APPROVED",
            ""
        ])
        with open(f"receipts/{account['username']}/{timestamp}.txt", "w", encoding="utf-8") as file:
            file.write(receipt_txt)

    def json(self):
        return self._data

    def insecure_txt(self):
        insecure_txt_db_json = json.dumps(
            self._insecure_text_db, separators=(',', ':'))
        table = []
        table.append(['account_id', 'created_at',
                      'username', 'name', 'pin', 'balance', 'transactions'])
        for account_id, account_data in self._data['accounts'].items():
            created_at = str(account_data['created_at'])
            username = account_data['username']
            name = account_data['name']
            pin = str(self._insecure_text_db[account_id])
            balance = format_balance(account_data['balance'])
            transactions = str(len(account_data['transactions']))
            table.append(
                [account_id, created_at, username, name, pin, balance, transactions])
        return f'{insecure_txt_db_json}\n\nIF YOU ARE NOT MR. DUNNE CLOSE THIS FILE IMMEDIATELY😡😡😡😡😡!!!!!!!!! YOU ARE INTELLECTUALLY TRESPASSING!!1!!1!\n{table_to_txt(table)}\n'


class ToolbarFrameToolbarPosition(Enum):
    TOP = auto()  # Toolbar at top of program.
    BOTTOM = auto()  # Toolbar at bottom of program.


def ToolbarFrame(body, toolbar_content, position):
    if position == ToolbarFrameToolbarPosition.TOP:
        return HSplit([toolbar_content, Frame(body)])

    toolbar = ConditionalContainer(
        content=toolbar_content,
        filter=renderer_height_is_known
    )

    return HSplit([Frame(body), toolbar])


def create_button_list_keybindings(buttons, key_previous, key_next):
    keybindings = KeyBindings()

    if len(buttons) > 1:
        # pylint: disable=invalid-unary-operand-type
        is_first_not_selected = ~has_focus(buttons[0])
        # pylint: disable=invalid-unary-operand-type
        is_last_not_selected = ~has_focus(buttons[-1])

        keybindings.add(key_previous, filter=is_first_not_selected)(
            focus_previous)
        keybindings.add(key_next, filter=is_last_not_selected)(focus_next)

    return keybindings


def create_vertical_button_list_keybindings(buttons):
    """Creates up/down keybindings to cycle through a vertical button list."""
    return create_button_list_keybindings(buttons, 'up', 'down')


def create_horizontal_button_list_keybindings(buttons):
    """Creates left/right keybindings to cycle through a horizontal list."""
    return create_button_list_keybindings(buttons, 'left', 'right')


db_file_path = 'data/db.json'
insecure_txt_file_path = 'data/____very_insecure_file____THERE_IS_NOTHING_IN_THIS_FILE______DO_NOT_OPEN__________DO_NOT_DO_IT______ONLY_FOR_MR_DUNNE.txt'


def load_db():
    with open(db_file_path, 'r', encoding="utf-8") as db_file, open(insecure_txt_file_path, 'r', encoding="utf-8") as insecure_txt_file:
        return DB(json.load(db_file), json.loads(insecure_txt_file.readline()))


def save_db(db):
    with open(db_file_path, 'w', encoding="utf-8") as file:
        json.dump(db.json(), file, separators=(',', ':'))
    with open(insecure_txt_file_path, 'w', encoding="utf-8") as file:
        file.write(db.insecure_txt())


def hash_new_password(password):
    # https://stackoverflow.com/questions/9594125/salt-and-hash-a-password-in-python/56915300#56915300
    """
    Hash the provided password with a randomly-generated salt and return the
    salt and hash to store in the database.
    """
    salt = os.urandom(16)
    pw_hash = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000)
    return salt, pw_hash


def is_correct_password(salt, pw_hash, password):
    """
    Given a previously-stored salt and hash, and a password provided by a user
    trying to log in, check whether the password is correct.
    """
    return hmac.compare_digest(
        pw_hash,
        hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000)
    )


def is_alnum_and_starts_with_al(str):
    return len(str) == 0 or (str.isalnum() and str[0].isalpha())


def LoginScreen(controller):
    error_msg = None

    def set_error_msg(msg):
        nonlocal error_msg
        error_msg = msg
        get_app().invalidate()

    def check_username_valid(username):
        if len(username.strip()) > 0:
            if not is_alnum_and_starts_with_al(username.strip()):
                get_app().layout.focus(username_textfield)
                set_error_msg(
                    "Username must start with a letter and only contain letters/numbers")
                return False
            return True
        get_app().layout.focus(username_textfield)
        set_error_msg("Username field is empty")
        return False

    def check_pin_valid(pin):
        if len(pin) == 4 and pin.isdecimal():
            return True
        get_app().layout.focus(pin_textfield)
        set_error_msg("Please enter 4 digits for Pin field")
        return False

    def on_username_textfield_accept(_buffer):
        if check_username_valid(username_textfield.text) and check_pin_valid(pin_textfield.text):
            set_error_msg(None)
            get_app().layout.focus(ok_button)
        return True  # Keeps text.

    def on_pin_textfield_accept(_buffer):
        if check_pin_valid(pin_textfield.text) and check_username_valid(username_textfield.text):
            set_error_msg(None)
            get_app().layout.focus(ok_button)
        return True  # Keeps text.

    def on_ok_clicked():
        username = username_textfield.text.strip().lower()
        pin = pin_textfield.text
        if not check_username_valid(username) or not check_pin_valid(pin_textfield.text):
            return
        set_error_msg(None)
        account = controller.state.session.db.get_account_from_username(
            username)
        if not account:
            set_error_msg("Incorrect username or pin")
            return
        account_pin = account['pin']
        if not is_correct_password(account_pin['salt'], account_pin['pw_hash'], pin):
            set_error_msg("Incorrect username or pin")
            return
        controller.set_state(MenuScreenState(
            Session(db=controller.state.session.db, account_id=account['account_id'])))

    def on_sign_up_clicked():
        # Go to Sign Up screen.
        new_state = SignUpScreenState(session=controller.state.session)
        controller.set_state(new_state)

    ok_button = Button(text="Login", handler=on_ok_clicked)
    exit_button = Button(text="Quit", handler=exit_current_app)
    sign_up_button = Button(text="Sign Up", handler=on_sign_up_clicked)
    username_textfield = TextArea(
        multiline=False,
        wrap_lines=False,
        accept_handler=on_username_textfield_accept,
        get_line_prefix=lambda _, __: '[username]: ',
        style=f'bg:{dialog_bg_color} {dialog_text_color} italic'
    )
    pin_textfield = TextArea(
        multiline=False,
        wrap_lines=False,
        password=True,
        accept_handler=on_pin_textfield_accept,
        get_line_prefix=lambda _, __: '[pin]: ',
        style=f'bg:{dialog_bg_color} {dialog_text_color} italic'
    )

    dialog = Dialog(
        title="SMH Bank",
        body=HSplit(
            [
                Label(text=HTML('<b>Login</b>'), dont_extend_height=True),
                username_textfield,
                pin_textfield,
                DynamicContainer(
                    get_container=lambda: Label(
                        text=error_msg or '',
                        dont_extend_height=True,
                        style=danger_text_color
                    )
                )
            ],
            padding=Dimension(preferred=1, max=1)
        ),
        buttons=[ok_button, sign_up_button, exit_button],
        with_background=True
    )

    return dialog


def SignUpScreen(controller):
    error_msg = None

    def set_error_msg(msg):
        nonlocal error_msg
        error_msg = msg
        get_app().invalidate()

    def check_username_valid(username):
        if len(username.strip()) > 0:
            if not controller.state.session.db.get_account_from_username(username.strip().lower()):
                if not is_alnum_and_starts_with_al(username.strip()):
                    get_app().layout.focus(username_textfield)
                    set_error_msg(
                        "Username must start with a letter and only contain letters/numbers")
                    return False
                return True
            get_app().layout.focus(username_textfield)
            set_error_msg("Username is already taken")
            return False
        get_app().layout.focus(username_textfield)
        set_error_msg("Username field is empty")
        return False

    def check_name_valid(name):
        if len(name.strip()) > 0:
            return True
        get_app().layout.focus(name_textfield)
        set_error_msg("Name field is empty")
        return False

    def check_pin_valid(pin):
        if len(pin) == 4 and pin.isdecimal():
            return True
        get_app().layout.focus(pin_textfield)
        set_error_msg("Please enter 4 digits for Pin field")
        return False

    def on_username_textfield_accept(_buffer):
        if check_username_valid(username_textfield.text) and check_name_valid(name_textfield.text) and check_pin_valid(pin_textfield.text):
            set_error_msg(None)
            get_app().layout.focus(ok_button)
        return True  # Keeps text.

    def on_name_textfield_accept(_buffer):
        if check_name_valid(name_textfield.text) and check_username_valid(username_textfield.text) and check_pin_valid(pin_textfield.text):
            set_error_msg(None)
            get_app().layout.focus(ok_button)
        return True  # Keeps text.

    def on_pin_textfield_accept(_buffer):
        if check_pin_valid(pin_textfield.text) and check_username_valid(username_textfield.text) and check_name_valid(name_textfield.text):
            set_error_msg(None)
            get_app().layout.focus(ok_button)
        return True  # Keeps text.

    def on_ok_clicked():
        username = username_textfield.text.strip().lower()
        name = name_textfield.text.strip()
        pin = pin_textfield.text
        if not check_username_valid(username) or not check_name_valid(username) or not check_pin_valid(pin_textfield.text):
            return
        set_error_msg(None)
        account_id = controller.state.session.db.make_account_with_details(
            username=username,
            name=name,
            pin=pin
        )
        controller.set_state(MenuScreenState(
            Session(db=controller.state.session.db, account_id=account_id)))

    def on_back_clicked():
        # Go to Sign Up screen.
        new_state = LoginScreenState(session=controller.state.session)
        controller.set_state(new_state)

    back_button = Button(text="Back", handler=on_back_clicked)
    ok_button = Button(text="Sign Up", handler=on_ok_clicked)
    exit_button = Button(text="Quit", handler=exit_current_app)
    username_textfield = TextArea(
        multiline=False,
        wrap_lines=False,
        accept_handler=on_username_textfield_accept,
        get_line_prefix=lambda _, __: '[username]: ',
        style=f'bg:{dialog_bg_color} {dialog_text_color} italic'
    )
    name_textfield = TextArea(
        multiline=False,
        wrap_lines=False,
        accept_handler=on_name_textfield_accept,
        get_line_prefix=lambda _, __: '[full name]: ',
        style=f'bg:{dialog_bg_color} {dialog_text_color} italic'
    )
    pin_textfield = TextArea(
        multiline=False,
        wrap_lines=False,
        password=True,
        accept_handler=on_pin_textfield_accept,
        get_line_prefix=lambda _, __: '[pin]: ',
        style=f'bg:{dialog_bg_color} {dialog_text_color} italic'
    )

    dialog = Dialog(
        title="SMH Bank",
        body=HSplit(
            [
                Label(text=HTML('<b>Sign Up</b>'), dont_extend_height=True),
                username_textfield,
                name_textfield,
                pin_textfield,
                DynamicContainer(
                    get_container=lambda: Label(
                        text=error_msg or '',
                        dont_extend_height=True,
                        style=danger_text_color
                    )
                )
            ],
            padding=Dimension(preferred=1, max=1)
        ),
        buttons=[back_button, ok_button, exit_button],
        with_background=True
    )

    return dialog


def MenuScreen(controller):
    def on_deposit_click():
        # Go to Deposit screen.
        new_state = DepositScreenState(session=controller.state.session)
        controller.set_state(new_state)

    def on_withdraw_click():
        # Go to Withdraw screen.
        new_state = WithdrawScreenState(session=controller.state.session)
        controller.set_state(new_state)

    def on_account_click():
        # Go to Account screen.
        new_state = AccountScreenState(session=controller.state.session)
        controller.set_state(new_state)

    buttons = [
        Button('Deposit', handler=on_deposit_click),
        Button('Withdraw', handler=on_withdraw_click),
        Button('My Account', handler=on_account_click),
        Button('quit', handler=exit_current_app)
    ]

    keybindings = create_vertical_button_list_keybindings(buttons)

    body = Box(
        VSplit([
            HSplit(
                children=buttons,
                padding=Dimension(preferred=1, max=1),
                key_bindings=keybindings
            )
        ]),
        style=f'bg:{bg_color} {text_color}'
    )

    account = controller.state.session.db.get_account_from_account_id(
        controller.state.session.account_id)
    toolbar_content = Window(
        content=FormattedTextControl(
            "Hi %s. What would you like to do today?" % account['name']),
        align=WindowAlign.CENTER,
        height=1
    )

    return ToolbarFrame(body=body, toolbar_content=toolbar_content, position=ToolbarFrameToolbarPosition.TOP)


def parse_amount_input(amount):
    amount_split = amount.split(".")
    dollars = int(amount_split[0] or 0)
    cents = 0
    if len(amount_split) == 2:
        cents = int(amount_split[1] or 0)
        if len(amount_split[1]) == 1:
            cents *= 10
    return dollars * 100 + cents


def DepositScreen(controller):
    account = controller.state.session.db.get_account_from_account_id(
        controller.state.session.account_id)
    error_msg = None

    def set_error_msg(msg):
        nonlocal error_msg
        error_msg = msg
        get_app().invalidate()

    amount_re = re.compile(r"^(\d+(\.\d{0,2})?|\.\d{1,2})$")

    def check_amount_valid(amount):
        if not amount_re.search(amount):
            get_app().layout.focus(amount_textfield)
            set_error_msg("Invalid amount")
            return False
        cents = parse_amount_input(amount)
        if cents == 0:
            get_app().layout.focus(amount_textfield)
            set_error_msg("Cannot deposit $0.00")
            return False
        if cents % 5 != 0:
            get_app().layout.focus(amount_textfield)
            set_error_msg("That is not a valid amount of cents")
            return False
        return True

    def on_amount_textfield_accept(_buffer):
        if check_amount_valid(amount_textfield.text):
            set_error_msg(None)
            get_app().layout.focus(ok_button)
        return True  # Keeps text.

    def on_ok_clicked():
        if not check_amount_valid(amount_textfield.text):
            return
        set_error_msg(None)
        cents = parse_amount_input(amount_textfield.text)
        controller.state.session.db.set_account_balance(
            controller.state.session.account_id, account['balance'] + cents)
        controller.state.session.db.record_account_transaction(
            controller.state.session.account_id, TransactionType.DEPOSIT, cents)
        controller.set_state(MenuScreenState(session=controller.state.session))

    def on_back_clicked():
        new_state = MenuScreenState(session=controller.state.session)
        controller.set_state(new_state)

    back_button = Button(text="Cancel", handler=on_back_clicked)
    ok_button = Button(text="Deposit Amount", handler=on_ok_clicked)
    exit_button = Button(text="Quit", handler=exit_current_app)
    amount_textfield = TextArea(
        multiline=False,
        wrap_lines=False,
        accept_handler=on_amount_textfield_accept,
        get_line_prefix=lambda _, __: '[amount]: $',
        style=f'bg:{dialog_bg_color} {dialog_text_color} italic'
    )

    dialog = Dialog(
        title=f"SMH Bank | {account['username']}",
        body=HSplit(
            [
                Label(text=HTML('<b>Deposit</b>'),
                      dont_extend_height=True),
                amount_textfield,
                DynamicContainer(
                    get_container=lambda: Label(
                        text=error_msg or '',
                        dont_extend_height=True,
                        style=danger_text_color
                    )
                )
            ],
            padding=Dimension(preferred=1, max=1)
        ),
        buttons=[back_button, ok_button, exit_button],
        with_background=True
    )

    return dialog


def WithdrawScreen(controller):
    account = controller.state.session.db.get_account_from_account_id(
        controller.state.session.account_id)
    error_msg = None

    def set_error_msg(msg):
        nonlocal error_msg
        error_msg = msg
        get_app().invalidate()

    amount_re = re.compile(r"^(\d+(\.\d{0,2})?|\.\d{1,2})$")

    def check_amount_valid(amount):
        if not amount_re.search(amount):
            get_app().layout.focus(amount_textfield)
            set_error_msg("Invalid amount")
            return False
        cents = parse_amount_input(amount)
        if cents == 0:
            get_app().layout.focus(amount_textfield)
            set_error_msg("Cannot withdraw $0.00")
            return False
        if cents % 5 != 0:
            get_app().layout.focus(amount_textfield)
            set_error_msg("That is not a valid amount of cents")
            return False
        if cents % 2000 != 0:
            get_app().layout.focus(amount_textfield)
            set_error_msg("Can only withdraw $20 bills")
            return False
        if cents > account['balance']:
            get_app().layout.focus(amount_textfield)
            set_error_msg("Insufficient funds")
            return False
        return True

    def on_amount_textfield_accept(_buffer):
        if check_amount_valid(amount_textfield.text):
            set_error_msg(None)
            get_app().layout.focus(ok_button)
        return True  # Keeps text.

    def on_ok_clicked():
        if not check_amount_valid(amount_textfield.text):
            return
        set_error_msg(None)
        cents = parse_amount_input(amount_textfield.text)
        controller.state.session.db.set_account_balance(
            controller.state.session.account_id, account['balance'] - cents)
        controller.state.session.db.record_account_transaction(
            controller.state.session.account_id, TransactionType.WITHDRAW, cents)
        controller.set_state(MenuScreenState(session=controller.state.session))

    def on_back_clicked():
        new_state = MenuScreenState(session=controller.state.session)
        controller.set_state(new_state)

    back_button = Button(text="Cancel", handler=on_back_clicked)
    ok_button = Button(text="Withdraw Amount", handler=on_ok_clicked)
    exit_button = Button(text="Quit", handler=exit_current_app)
    amount_textfield = TextArea(
        multiline=False,
        wrap_lines=False,
        accept_handler=on_amount_textfield_accept,
        get_line_prefix=lambda _, __: '[amount]: $',
        style=f'bg:{dialog_bg_color} {dialog_text_color} italic'
    )

    dialog = Dialog(
        title=f"SMH Bank | {account['username']}",
        body=HSplit(
            [
                Label(text=HTML('<b>Withdraw</b>'),
                      dont_extend_height=True),
                amount_textfield,
                DynamicContainer(
                    get_container=lambda: Label(
                        text=error_msg or '',
                        dont_extend_height=True,
                        style=danger_text_color
                    )
                )
            ],
            padding=Dimension(preferred=1, max=1)
        ),
        buttons=[back_button, ok_button, exit_button],
        with_background=True
    )

    return dialog


def prettydate(d):
    # https://stackoverflow.com/questions/410221/natural-relative-days-in-python
    diff = datetime.now() - d
    s = diff.seconds
    if diff.days > 7 or diff.days < 0:
        return d.strftime('%d %b %y')
    elif diff.days == 1:
        return '1 day ago'
    elif diff.days > 1:
        return '{} days ago'.format(diff.days)
    elif s <= 1:
        return 'just now'
    elif s < 60:
        return '{} seconds ago'.format(s)
    elif s < 120:
        return '1 minute ago'
    elif s < 3600:
        return '{} minutes ago'.format(int(s/60))
    elif s < 7200:
        return '1 hour ago'
    else:
        return '{} hours ago'.format(int(s/3600))


def AccountScreen(controller):
    body_keybindings = KeyBindings()

    @body_keybindings.add('escape')
    def _body_on_key_esc(_):
        app = get_app()
        first_toolbar_button = toolbar_buttons[0]
        app.layout.focus(first_toolbar_button)

    account = controller.state.session.db.get_account_from_account_id(
        controller.state.session.account_id)

    def on_view_transactions_click():
        new_state = TransactionsScreenState(
            session=controller.state.session, filter=TransactionsScreenFilter.BOTH)
        controller.set_state(new_state)

    def on_change_username_click():
        new_state = ChangeUsernameScreenState(session=controller.state.session)
        controller.set_state(new_state)

    def on_change_name_click():
        new_state = ChangeNameScreenState(session=controller.state.session)
        controller.set_state(new_state)

    def on_change_pin_click():
        new_state = ChangePinScreenState(session=controller.state.session)
        controller.set_state(new_state)

    def on_logout_click():
        controller.set_state(LoginScreenState(
            session=Session(db=controller.state.session.db)))

    def on_delete_account_click():
        new_state = DeleteAccount1ScreenState(session=controller.state.session)
        controller.set_state(new_state)

    body_buttons = [
        Button('view', pad_width=2, handler=on_view_transactions_click),
        Button('change', handler=on_change_username_click),
        Button('change', handler=on_change_name_click),
        Button('change', handler=on_change_pin_click),
        Button("Logout", handler=on_logout_click)
    ]
    body_buttons_iter = iter(body_buttons)
    global global__default_target_focus
    global__default_target_focus = body_buttons[0]

    body = Box(
        HSplit(
            [
                Label(text=HTML('<b><i>My Account</i></b>')),
                Label(text=HTML(
                    f"<i>Account created {prettydate(account['created_at'])}</i>")),
                Label(text=HTML(
                    f"<i>Your account's balance is {format_balance(account['balance'])}</i>")),
                VSplit([
                    Label(
                        text=f"Transactions: {len(account['transactions'])}"),
                    next(body_buttons_iter),
                ]),
                VSplit([
                    Label(
                        text=f"Username: {account['username']}"),
                    next(body_buttons_iter),
                ]),
                VSplit([
                    Label(text=f"Full Name: {account['name']}"),
                    next(body_buttons_iter),
                ]),
                VSplit([
                    Label(text="Pin: ****"),
                    next(body_buttons_iter),
                ]),
                VSplit(
                    [next(body_buttons_iter)],
                    align=HorizontalAlign.CENTER
                ),
                VSplit(
                    [Button("Click to Delete Account",
                            handler=on_delete_account_click,
                            class_="danger_button")],
                    align=HorizontalAlign.CENTER
                )
            ],
            key_bindings=merge_key_bindings([
                body_keybindings, create_vertical_button_list_keybindings(body_buttons)]),
            padding=Dimension(preferred=1, max=1)
        ),
        style=f'bg:{bg_color} {text_color}'
    )

    def on_back_click():
        # Go to menu screen.
        new_state = MenuScreenState(session=controller.state.session)
        controller.set_state(new_state)

    toolbar_buttons = [
        Button('back', handler=on_back_click, class_='toolbar_button'),
        Button('quit', handler=exit_current_app, class_='toolbar_button')
    ]

    toolbar_content = Box(
        VSplit(
            children=toolbar_buttons,
            align=HorizontalAlign.CENTER,
            padding=Dimension(preferred=10, max=10),
            key_bindings=create_horizontal_button_list_keybindings(
                toolbar_buttons)
        ),
        height=1
    )

    return ToolbarFrame(body, toolbar_content, position=ToolbarFrameToolbarPosition.TOP)


class TablePrintOut:
    txt = ''

    def write(self, txt):
        self.txt += txt

    def flush(self):
        pass


def TransactionsScreen(controller):
    body_keybindings = KeyBindings()

    @body_keybindings.add('escape')
    def _body_on_key_esc(_):
        app = get_app()
        first_toolbar_button = toolbar_buttons[0]
        app.layout.focus(first_toolbar_button)

    account = controller.state.session.db.get_account_from_account_id(
        controller.state.session.account_id)

    def filter_deposits():
        controller.set_state(TransactionsScreenState(
            session=controller.state.session, filter=TransactionsScreenFilter.DEPOSIT_ONLY))

    def filter_withdrawals():
        controller.set_state(TransactionsScreenState(
            session=controller.state.session, filter=TransactionsScreenFilter.WITHDRAW_ONLY))

    def filter_both():
        controller.set_state(TransactionsScreenState(
            session=controller.state.session, filter=TransactionsScreenFilter.BOTH))

    body_buttons = [
        Button('Deposits', handler=filter_deposits),
        Button('Withdrawals', handler=filter_withdrawals),
        Button('Both', handler=filter_both)
    ]

    table_rows = [
        [
            'DEPOSIT' if transaction['type'] == TransactionType.DEPOSIT else 'WITHDRAW',
            format_balance(transaction['value']),
            prettydate(transaction['timestamp'])
        ] for transaction in account['transactions'][::-1] if (
            True if controller.state.filter == TransactionsScreenFilter.BOTH else (
                transaction['type'] == TransactionType.DEPOSIT
                if controller.state.filter == TransactionsScreenFilter.DEPOSIT_ONLY
                else transaction['type'] == TransactionType.WITHDRAW
            )
        )
    ]
    if len(table_rows) == 0:
        table_txt = 'No transactions'
    else:
        table_out = TablePrintOut()
        tp.table(table_rows, ['Type', 'Value', 'Time'],
                 style='round', out=table_out)
        table_txt = table_out.txt
    body = Box(
        HSplit(
            [
                VSplit(
                    [Label(text=HTML('<b><i>Transactions  </i></b>'))] + body_buttons),
                TextArea(table_txt, width=max(
                    len(l) for l in table_txt.split('\n'))+3, focusable=False, scrollbar=True)
            ],
            align=VerticalAlign.TOP,
            key_bindings=merge_key_bindings(
                [body_keybindings, create_horizontal_button_list_keybindings(body_buttons)]),
            padding=Dimension(preferred=1, max=1)
        ),
        padding_top=Dimension(preferred=1, max=1),
        style=f'bg:{bg_color} {text_color}'
    )

    global global__default_target_focus
    global__default_target_focus = (
        body_buttons[0] if controller.state.filter == TransactionsScreenFilter.DEPOSIT_ONLY else (
            body_buttons[1] if controller.state.filter == TransactionsScreenFilter.WITHDRAW_ONLY else body_buttons[2]
        )
    )

    def on_back_click():
        new_state = AccountScreenState(session=controller.state.session)
        controller.set_state(new_state)

    toolbar_buttons = [
        Button('back', handler=on_back_click, class_='toolbar_button'),
        Button('quit', handler=exit_current_app, class_='toolbar_button')
    ]

    toolbar_content = Box(
        VSplit(
            children=toolbar_buttons,
            align=HorizontalAlign.CENTER,
            padding=Dimension(preferred=10, max=10),
            key_bindings=create_horizontal_button_list_keybindings(
                toolbar_buttons)
        ),
        height=1
    )

    return ToolbarFrame(body, toolbar_content, position=ToolbarFrameToolbarPosition.TOP)


def ChangeUsernameScreen(controller):
    account = controller.state.session.db.get_account_from_account_id(
        controller.state.session.account_id)
    error_msg = None

    def set_error_msg(msg):
        nonlocal error_msg
        error_msg = msg
        get_app().invalidate()

    def check_username_valid(username):
        if len(username.strip()) == 0:
            get_app().layout.focus(username_textfield)
            set_error_msg("Username field is empty")
            return False
        if username == account['username']:
            get_app().layout.focus(username_textfield)
            set_error_msg("That is your current username")
            return False
        if not controller.state.session.db.get_account_from_username(username.strip().lower()):
            if not is_alnum_and_starts_with_al(username.strip()):
                get_app().layout.focus(username_textfield)
                set_error_msg(
                    "Username must start with a letter and only contain letters/numbers")
                return False
            return True
        get_app().layout.focus(username_textfield)
        set_error_msg("Username is already taken")
        return False

    def on_username_textfield_accept(_buffer):
        if check_username_valid(username_textfield.text):
            set_error_msg(None)
            get_app().layout.focus(ok_button)
        return True  # Keeps text.

    def on_ok_clicked():
        username = username_textfield.text.strip().lower()
        if not check_username_valid(username):
            return
        set_error_msg(None)
        controller.state.session.db.change_account_username(
            controller.state.session.account_id, username)
        controller.set_state(MenuScreenState(session=controller.state.session))

    def on_back_clicked():
        new_state = AccountScreenState(session=controller.state.session)
        controller.set_state(new_state)

    back_button = Button(text="Cancel", handler=on_back_clicked)
    ok_button = Button(text="Change Username", handler=on_ok_clicked)
    exit_button = Button(text="Quit", handler=exit_current_app)
    username_textfield = TextArea(
        multiline=False,
        wrap_lines=False,
        accept_handler=on_username_textfield_accept,
        get_line_prefix=lambda _, __: '[new username]: ',
        style=f'bg:{dialog_bg_color} {dialog_text_color} italic'
    )

    dialog = Dialog(
        title=f"SMH Bank | {account['username']}",
        body=HSplit(
            [
                Label(text=HTML('<b>Change Username</b>'),
                      dont_extend_height=True),
                username_textfield,
                DynamicContainer(
                    get_container=lambda: Label(
                        text=error_msg or '',
                        dont_extend_height=True,
                        style=danger_text_color
                    )
                )
            ],
            padding=Dimension(preferred=1, max=1)
        ),
        buttons=[back_button, ok_button, exit_button],
        with_background=True
    )

    return dialog


def ChangeNameScreen(controller):
    account = controller.state.session.db.get_account_from_account_id(
        controller.state.session.account_id)
    error_msg = None

    def set_error_msg(msg):
        nonlocal error_msg
        error_msg = msg
        get_app().invalidate()

    def check_name_valid(name):
        if len(name.strip()) > 0:
            if name == account['name']:
                get_app().layout.focus(name_textfield)
                set_error_msg("That is your current name")
                return False
            return True
        get_app().layout.focus(name_textfield)
        set_error_msg("Name field is empty")
        return False

    def on_name_textfield_accept(_buffer):
        if check_name_valid(name_textfield.text):
            set_error_msg(None)
            get_app().layout.focus(ok_button)
        return True  # Keeps text.

    def on_ok_clicked():
        name = name_textfield.text.strip()
        if not check_name_valid(name):
            return
        set_error_msg(None)
        controller.state.session.db.change_account_name(
            controller.state.session.account_id, name)
        controller.set_state(MenuScreenState(session=controller.state.session))

    def on_back_clicked():
        new_state = AccountScreenState(session=controller.state.session)
        controller.set_state(new_state)

    back_button = Button(text="Cancel", handler=on_back_clicked)
    ok_button = Button(text="Change Name", handler=on_ok_clicked)
    exit_button = Button(text="Quit", handler=exit_current_app)
    name_textfield = TextArea(
        multiline=False,
        wrap_lines=False,
        accept_handler=on_name_textfield_accept,
        get_line_prefix=lambda _, __: '[new full name]: ',
        style=f'bg:{dialog_bg_color} {dialog_text_color} italic'
    )

    dialog = Dialog(
        title=f"SMH Bank | {account['username']}",
        body=HSplit(
            [
                Label(text=HTML('<b>Change Name</b>'),
                      dont_extend_height=True),
                name_textfield,
                DynamicContainer(
                    get_container=lambda: Label(
                        text=error_msg or '',
                        dont_extend_height=True,
                        style=danger_text_color
                    )
                )
            ],
            padding=Dimension(preferred=1, max=1)
        ),
        buttons=[back_button, ok_button, exit_button],
        with_background=True
    )

    return dialog


def ChangePinScreen(controller):
    account = controller.state.session.db.get_account_from_account_id(
        controller.state.session.account_id)
    error_msg = None

    def set_error_msg(msg):
        nonlocal error_msg
        error_msg = msg
        get_app().invalidate()

    def check_pin_valid(pin):
        if len(pin) == 4 and pin.isdecimal():
            return True
        get_app().layout.focus(pin_textfield)
        set_error_msg("Please enter 4 digits for Pin field")
        return False

    def on_pin_textfield_accept(_buffer):
        if check_pin_valid(pin_textfield.text):
            set_error_msg(None)
            get_app().layout.focus(ok_button)
        return True  # Keeps text.

    def on_ok_clicked():
        pin = pin_textfield.text
        if not check_pin_valid(pin):
            return
        set_error_msg(None)
        controller.state.session.db.change_account_pin(
            controller.state.session.account_id, pin)
        controller.set_state(MenuScreenState(session=controller.state.session))

    def on_back_clicked():
        new_state = AccountScreenState(session=controller.state.session)
        controller.set_state(new_state)

    back_button = Button(text="Cancel", handler=on_back_clicked)
    ok_button = Button(text="Change Pin", handler=on_ok_clicked)
    exit_button = Button(text="Quit", handler=exit_current_app)
    pin_textfield = TextArea(
        multiline=False,
        wrap_lines=False,
        password=True,
        accept_handler=on_pin_textfield_accept,
        get_line_prefix=lambda _, __: '[new pin]: ',
        style=f'bg:{dialog_bg_color} {dialog_text_color} italic'
    )

    dialog = Dialog(
        title=f"SMH Bank | {account['username']}",
        body=HSplit(
            [
                Label(text=HTML('<b>Change Pin</b>'),
                      dont_extend_height=True),
                pin_textfield,
                DynamicContainer(
                    get_container=lambda: Label(
                        text=error_msg or '',
                        dont_extend_height=True,
                        style=danger_text_color
                    )
                )
            ],
            padding=Dimension(preferred=1, max=1)
        ),
        buttons=[back_button, ok_button, exit_button],
        with_background=True
    )

    return dialog


def DeleteAccount1Screen(controller):
    account = controller.state.session.db.get_account_from_account_id(
        controller.state.session.account_id)

    def on_ok_clicked():
        controller.set_state(DeleteAccount2ScreenState(
            session=controller.state.session))

    def on_back_clicked():
        new_state = AccountScreenState(session=controller.state.session)
        controller.set_state(new_state)

    back_button = Button(text="Cancel", handler=on_back_clicked)
    ok_button = Button(text="Delete Account",
                       handler=on_ok_clicked, class_="dialog_danger_button")
    exit_button = Button(text="Quit", handler=exit_current_app)

    dialog = Dialog(
        title=f"SMH Bank | {account['username']}",
        body=HSplit(
            [
                Label(text=HTML('<b>Delete Account</b>'),
                      dont_extend_height=True),
                TextArea(
                    "Are you sure you want to delete your account? This action is not reversible and you will permanently lose all the money in your account",
                    focusable=False,
                    scrollbar=True,
                    style=f"bg:{dialog_bg_color} {dialog_text_color}"
                )
            ],
            padding=Dimension(preferred=1, max=1)
        ),
        buttons=[back_button, ok_button, exit_button],
        with_background=True
    )

    return dialog


def DeleteAccount2Screen(controller):
    account = controller.state.session.db.get_account_from_account_id(
        controller.state.session.account_id)
    error_msg = None

    def set_error_msg(msg):
        nonlocal error_msg
        error_msg = msg
        get_app().invalidate()

    def check_username_valid(username):
        if username.lower() == account['username']:
            return True
        get_app().layout.focus(username_textfield)
        set_error_msg("That is not your username")
        return False

    def on_username_textfield_accept(_buffer):
        if check_username_valid(username_textfield.text):
            set_error_msg(None)
            get_app().layout.focus(ok_button)
        return True  # Keeps text.

    def on_ok_clicked():
        if not check_username_valid(username_textfield.text):
            return
        controller.state.session.db.delete_account(
            controller.state.session.account_id)
        controller.set_state(LoginScreenState(
            session=Session(db=controller.state.session.db)))

    def on_back_clicked():
        new_state = AccountScreenState(session=controller.state.session)
        controller.set_state(new_state)

    back_button = Button(text="Cancel", handler=on_back_clicked)
    ok_button = Button(text="Delete Account",
                       handler=on_ok_clicked, class_="dialog_danger_button")
    exit_button = Button(text="Quit", handler=exit_current_app)
    username_textfield = TextArea(
        multiline=False,
        wrap_lines=False,
        accept_handler=on_username_textfield_accept,
        get_line_prefix=lambda _, __: '[username]: ',
        style=f'bg:{dialog_bg_color} {dialog_text_color} italic'
    )

    dialog = Dialog(
        title=f"SMH Bank | {account['username']}",
        body=HSplit(
            [
                Label(text=HTML('<b>Delete Account</b>'),
                      dont_extend_height=True),
                Label(
                    "Confirm your username to delete your account",
                    dont_extend_height=True
                ),
                username_textfield,
                DynamicContainer(
                    get_container=lambda: Label(
                        text=error_msg or '',
                        dont_extend_height=True,
                        style=danger_text_color
                    )
                )
            ],
            padding=Dimension(preferred=1, max=1)
        ),
        buttons=[back_button, ok_button, exit_button],
        with_background=True
    )

    return dialog


def RootScreen(controller):
    state = controller.state

    # Render screen associated with state screen type.
    if state.root_screen_type == RootScreenType.LOGIN:
        return LoginScreen(controller)

    if state.root_screen_type == RootScreenType.SIGN_UP:
        return SignUpScreen(controller)

    if state.root_screen_type == RootScreenType.MENU:
        return MenuScreen(controller)

    if state.root_screen_type == RootScreenType.DEPOSIT:
        return DepositScreen(controller)

    if state.root_screen_type == RootScreenType.WITHDRAW:
        return WithdrawScreen(controller)

    if state.root_screen_type == RootScreenType.ACCOUNT:
        return AccountScreen(controller)

    if state.root_screen_type == RootScreenType.TRANSACTIONS:
        return TransactionsScreen(controller)

    if state.root_screen_type == RootScreenType.CHANGE_USERNAME:
        return ChangeUsernameScreen(controller)

    if state.root_screen_type == RootScreenType.CHANGE_NAME:
        return ChangeNameScreen(controller)

    if state.root_screen_type == RootScreenType.CHANGE_PIN:
        return ChangePinScreen(controller)

    if state.root_screen_type == RootScreenType.DELETE_ACCOUNT_1:
        return DeleteAccount1Screen(controller)

    if state.root_screen_type == RootScreenType.DELETE_ACCOUNT_2:
        return DeleteAccount2Screen(controller)


class Controller:
    # Controls state management and re-rendering according to changed state.
    def __init__(self, state, Screen):
        self._Screen = Screen
        self._container = DynamicContainer(lambda: self._current_screen)
        self.set_state(state)

    def set_state(self, new_state):
        self.state = new_state
        self._current_screen = self._Screen(self)

    def __pt_container__(self):
        return self._container


def RootController(root_state=LoginScreenState(session=Session(db=load_db()))):
    return Controller(root_state, RootScreen)


bg_color = '#82aba4'
dialog_bg_color = '#36213e'
dialog_text_color = '#ffffff'
text_color = '#ffffff'
danger_text_color = '#dd0000'
root_style = Style.from_dict({
    'dialog': f'bg:{bg_color}',
    'dialog frame.label': f'bg:{dialog_bg_color} {dialog_text_color}',
    'dialog.body': f'bg:{dialog_bg_color} {dialog_text_color}',
    'dialog shadow': 'bg:#63968d',
    'button.focused': f'bg:{text_color} {bg_color}',
    'toolbar_button.focused': f'bg:{bg_color} {text_color}',
    'danger_button': f'bg:{bg_color} {danger_text_color}',
    'danger_button.focused': f'bg:{danger_text_color} {text_color}',
    'dialog_danger_button': f'bg:{dialog_bg_color} {danger_text_color}',
    'dialog_danger_button.focused': f'bg:{danger_text_color} {text_color}',
})


def focus_first_element():
    """Places focus on the first element on the screen for the current running
    application."""
    app = get_app()

    # Focus first window.
    app.layout.focus(next(app.layout.find_all_windows()))

    # Focus first ui element, eg. button.
    app.layout.focus_next()


# Keybindings.
tab_bindings = KeyBindings()
tab_bindings.add('tab')(focus_next)
tab_bindings.add('s-tab')(focus_previous)

exit_bindings = KeyBindings()
exit_bindings.add('c-c')(lambda e: exit_current_app())


def build_application():
    """Creates prompt_toolkit application."""
    layout = Layout(RootController())

    def ensure_focus(_):
        """Ensures that at least one element on the screen is focused"""
        app = get_app()

        # When switching screens or something prompt_toolkit doesn't recognize
        # the new focusable elements added to the screen. This will ensure that
        # at least one container/ui is marked as focusable so the screen can be
        # interacted with.

        global global__default_target_focus  # Preferred element to be focused.

        if global__default_target_focus:
            app.layout.focus(global__default_target_focus)
            global__default_target_focus = None  # Reset for next render.

            app.invalidate()  # Trigger re-render.
        elif len(app.layout.get_visible_focusable_windows()) == 0:
            focus_first_element()

            app.invalidate()  # Trigger re-render.

    keybindings = KeyBindings()
    keybindings.add('tab')(focus_next)
    keybindings.add('s-tab')(focus_previous)

    @keybindings.add('c-c')
    def _on_key_ctrl_c(_):
        exit_current_app()

    return Application(
        layout=layout,
        key_bindings=keybindings,
        full_screen=True,
        mouse_support=True,
        after_render=ensure_focus,
        style=root_style,
        color_depth=ColorDepth.DEPTH_24_BIT if system() == 'Windows' else None
    )


def main():
    # Create and run application.
    build_application().run()


if __name__ == "__main__":
    main()
