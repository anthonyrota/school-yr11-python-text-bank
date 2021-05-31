from abc import ABC, abstractmethod
from functools import reduce
from enum import Enum, auto
from time import time as now
from platform import system
from uuid import uuid4
import os
import hashlib
import hmac
import json
import base64

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

# The target element to focus when switching scenes. if none, equals None.
# this is safe because only one app can run at a time.
global__default_target_focus = None


def exit_current_app():
    """Exits the current application, restoring previous terminal state."""
    get_app().exit()


class RootScreenType(Enum):
    LOGIN = auto()
    MENU = auto()
    CHECK_BALANCE = auto()
    DEPOSIT = auto()
    WITHDRAW = auto()
    ACCOUNT = auto()


class LoginScreenState:
    """Initial screen where user logs in using their credentials. Users can also
    sign up to create a new account. After entering the form the user is taken to
    the menu screen."""
    root_screen_type = RootScreenType.LOGIN

    def __init__(self, session):
        self.session = session


class MenuScreenState:
    """Screen where user can navigate to all the other screens/use ATM's functions"""
    root_screen_type = RootScreenType.MENU

    def __init__(self, session):
        self.session = session


class CheckBalanceScreenState:
    root_screen_type = RootScreenType.CHECK_BALANCE

    def __init__(self, session):
        self.session = session


class DepositScreenState:
    root_screen_type = RootScreenType.DEPOSIT

    def __init__(self, session):
        self.session = session


class WithdrawScreenState:
    root_screen_type = RootScreenType.WITHDRAW

    def __init__(self, session):
        self.session = session


class AccountScreenState:
    root_screen_type = RootScreenType.ACCOUNT

    def __init__(self, session):
        self.session = session


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
            "balance": account['balance']
        }

    def get_account_from_username(self, username):
        account_username_to_account_id = self._data['account_username_to_account_id']
        if username not in account_username_to_account_id:
            return None
        account_id = account_username_to_account_id[username]
        return self.get_account_from_account_id(account_id)

    def json(self):
        return self._data

    def insecure_txt(self):
        insecure_txt_db_json = json.dumps(
            self._insecure_text_db, separators=(',', ':'))
        table = []
        table.append(['account_id', 'username', 'name', 'pin', 'balance'])
        for account_id, account_data in self._data['accounts'].items():
            username = account_data['username']
            name = account_data['name']
            pin = str(self._insecure_text_db[account_id])
            balance_raw = str(account_data['balance'])
            dollars = balance_raw[:-2]
            cents = balance_raw[-2:]
            balance = f'${dollars}.{cents}'
            table.append([account_id, username, name, pin, balance])
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

# TODO: db versioning and locking.


def load_db():
    with open(db_file_path, 'r') as db_file, open(insecure_txt_file_path, 'r') as insecure_txt_file:
        return DB(json.load(db_file), json.loads(insecure_txt_file.readline()))


def save_db(db):
    with open(db_file_path, 'w') as file:
        json.dump(db.json(), file)
    with open(insecure_txt_file_path, 'w') as file:
        file.write(db.insecure_txt())

# https://stackoverflow.com/questions/9594125/salt-and-hash-a-password-in-python/56915300#56915300


def hash_new_password(password):
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


def LoginScreen(controller):
    error_msg = None

    def set_error_msg(msg):
        nonlocal error_msg
        error_msg = msg
        get_app().invalidate()

    def check_username_valid(username):
        if len(username.strip()) > 0:
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

    ok_button = Button(text="Login", handler=on_ok_clicked)
    exit_button = Button(text="Quit", handler=exit_current_app)
    username_textfield = TextArea(
        multiline=False,
        wrap_lines=False,
        accept_handler=on_username_textfield_accept,
        get_line_prefix=lambda _, __: '[username]: ',
        style='bg:#88ff88 #000000 italic'
    )
    pin_textfield = TextArea(
        multiline=False,
        wrap_lines=False,
        password=True,
        accept_handler=on_pin_textfield_accept,
        get_line_prefix=lambda _, __: '[password]: ',
        style='bg:#88ff88 #000000 italic'
    )

    dialog = Dialog(
        title="SMH Bank",
        body=HSplit(
            [
                Label(text=HTML('<u>Login</u>'), dont_extend_height=True),
                username_textfield,
                pin_textfield,
                DynamicContainer(
                    get_container=lambda: Label(
                        text=error_msg or '',
                        dont_extend_height=True,
                        style="#dd0000"
                    )
                )
            ],
            padding=Dimension(preferred=1, max=1)
        ),
        buttons=[ok_button, exit_button],
        with_background=True
    )

    return dialog


def MenuScreen(controller):
    def on_check_balance_click():
        # Go to Check Balance screen.
        new_state = CheckBalanceScreenState(session=controller.state.session)
        controller.set_state(new_state)

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
        Button('Check Balance', handler=on_check_balance_click),
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
        style='bg:#88ff88 #000000'
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


def CheckBalanceScreen(controller):
    body = Box(
        TextArea(
            "Check Balance",
            focusable=False,
            scrollbar=True
        ),
        padding=0,
        padding_left=1,
        padding_right=1,
        style='bg:#88ff88 #000000'
    )

    def on_back_click():
        # Go to menu screen.
        new_state = MenuScreenState(session=controller.state.session)
        controller.set_state(new_state)

    buttons = [
        Button('back', handler=on_back_click),
        Button('quit', handler=exit_current_app)
    ]

    keybindings = create_horizontal_button_list_keybindings(buttons)

    toolbar_content = Box(
        VSplit(
            children=buttons,
            align=HorizontalAlign.CENTER,
            padding=Dimension(preferred=10, max=10),
            key_bindings=keybindings
        ),
        height=1
    )

    return ToolbarFrame(body, toolbar_content, position=ToolbarFrameToolbarPosition.BOTTOM)


def DepositScreen(controller):
    body = Box(
        TextArea(
            "Deposit",
            focusable=False,
            scrollbar=True
        ),
        padding=0,
        padding_left=1,
        padding_right=1,
        style='bg:#88ff88 #000000'
    )

    def on_back_click():
        # Go to menu screen.
        new_state = MenuScreenState(session=controller.state.session)
        controller.set_state(new_state)

    buttons = [
        Button('back', handler=on_back_click),
        Button('quit', handler=exit_current_app)
    ]

    keybindings = create_horizontal_button_list_keybindings(buttons)

    toolbar_content = Box(
        VSplit(
            children=buttons,
            align=HorizontalAlign.CENTER,
            padding=Dimension(preferred=10, max=10),
            key_bindings=keybindings
        ),
        height=1
    )

    return ToolbarFrame(body, toolbar_content, position=ToolbarFrameToolbarPosition.BOTTOM)


def WithdrawScreen(controller):
    body = Box(
        TextArea(
            "Withdraw",
            focusable=False,
            scrollbar=True
        ),
        padding=0,
        padding_left=1,
        padding_right=1,
        style='bg:#88ff88 #000000'
    )

    def on_back_click():
        # Go to menu screen.
        new_state = MenuScreenState(session=controller.state.session)
        controller.set_state(new_state)

    buttons = [
        Button('back', handler=on_back_click),
        Button('quit', handler=exit_current_app)
    ]

    keybindings = create_horizontal_button_list_keybindings(buttons)

    toolbar_content = Box(
        VSplit(
            children=buttons,
            align=HorizontalAlign.CENTER,
            padding=Dimension(preferred=10, max=10),
            key_bindings=keybindings
        ),
        height=1
    )

    return ToolbarFrame(body, toolbar_content, position=ToolbarFrameToolbarPosition.BOTTOM)


def AccountScreen(controller):
    body = Box(
        TextArea(
            "Account",
            focusable=False,
            scrollbar=True
        ),
        padding=0,
        padding_left=1,
        padding_right=1,
        style='bg:#88ff88 #000000'
    )

    def on_back_click():
        # Go to menu screen.
        new_state = MenuScreenState(session=controller.state.session)
        controller.set_state(new_state)

    buttons = [
        Button('back', handler=on_back_click),
        Button('quit', handler=exit_current_app)
    ]

    keybindings = create_horizontal_button_list_keybindings(buttons)

    toolbar_content = Box(
        VSplit(
            children=buttons,
            align=HorizontalAlign.CENTER,
            padding=Dimension(preferred=10, max=10),
            key_bindings=keybindings
        ),
        height=1
    )

    return ToolbarFrame(body, toolbar_content, position=ToolbarFrameToolbarPosition.BOTTOM)


def RootScreen(controller):
    state = controller.state

    # Render screen associated with state screen type.
    if state.root_screen_type == RootScreenType.LOGIN:
        return LoginScreen(controller)

    if state.root_screen_type == RootScreenType.MENU:
        return MenuScreen(controller)

    if state.root_screen_type == RootScreenType.CHECK_BALANCE:
        return CheckBalanceScreen(controller)

    if state.root_screen_type == RootScreenType.DEPOSIT:
        return DepositScreen(controller)

    if state.root_screen_type == RootScreenType.WITHDRAW:
        return WithdrawScreen(controller)

    if state.root_screen_type == RootScreenType.ACCOUNT:
        return AccountScreen(controller)


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


root_style = Style.from_dict({
    'dialog': 'bg:#88ff88',
    'dialog frame.label': 'bg:#000000 #00ff00',
    'dialog.body': 'bg:#000000 #00ff00',
    'dialog shadow': 'bg:#00aa00',
    'button.focused': 'bg:#228822',
    'dialog.body text-area last-line': 'nounderline'
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
