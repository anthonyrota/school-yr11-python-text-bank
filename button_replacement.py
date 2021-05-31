# Replacement for the built in button class (removes curser + styling).

from typing import Optional, Callable

from prompt_toolkit.application.current import get_app
from prompt_toolkit.formatted_text import (
    StyleAndTextTuples,
)
from prompt_toolkit.key_binding.key_bindings import KeyBindings
from prompt_toolkit.layout.containers import (
    Container,
    Window,
    WindowAlign,
)
from prompt_toolkit.layout.controls import FormattedTextControl
from prompt_toolkit.mouse_events import MouseEvent, MouseEventType
from prompt_toolkit.layout.dimension import Dimension


class Button:
    """
    Clickable button.

    :param text: The caption for the button.
    :param handler: `None` or callable. Called when the button is clicked.
    :param width: Width of the button.
    :param stripped: If true display without '<' and '>
    """

    def __init__(
        self,
        text: str,
        handler: Optional[Callable[[], None]] = None,
        width: int = None,
        focusable: bool = True,
        class_=None
    ) -> None:
        self.text = text
        self.handler = handler
        self.width = width
        self.focusable = focusable

        if width is None:
            self.width = max(12, len(text)+2)

        self.control = FormattedTextControl(
            self._get_text_fragments,
            key_bindings=self._get_key_bindings(),
            focusable=focusable,
        )

        def get_style() -> str:
            if class_:
                return 'class:%s' % (class_)
            if get_app().layout.has_focus(self):
                return "class:button.focused"
            else:
                return "class:button"

        self.window = Window(
            self.control,
            align=WindowAlign.CENTER,
            height=1,
            width=Dimension(preferred=self.width, max=self.width),
            style=get_style,
            dont_extend_width=True,
            dont_extend_height=True,
            always_hide_cursor=True  # Stops curser from showing when selected
        )

    def _get_text_fragments(self) -> StyleAndTextTuples:
        text = ("{:^%s}" % (self.width)).format(self.text)

        def handler(mouse_event: MouseEvent) -> None:
            if (
                self.handler is not None
                and mouse_event.event_type == MouseEventType.MOUSE_UP
            ):
                self.handler()

        return [
            ("[SetCursorPosition]", ""),
            ("class:button.text", text, handler)
        ]

    def _get_key_bindings(self) -> KeyBindings:
        " Key bindings for the Button. "
        kb = KeyBindings()

        @kb.add(" ")
        @kb.add("enter")
        def _(event) -> None:
            if self.handler is not None:
                self.handler()

        return kb

    # this is what prompt_toolkit calls to actually get the content of a component
    def __pt_container__(self) -> Container:
        return self.window
