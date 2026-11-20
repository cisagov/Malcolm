"""Exercise the real installer yes/no interfaces without user interaction."""

from types import SimpleNamespace
from unittest.mock import Mock

import pytest

import malcolm_common as common

ACCEPT = common.UserInputDefaultsBehavior.DefaultsAccept
PROMPT = common.UserInputDefaultsBehavior.DefaultsPrompt
NONINTERACTIVE = common.UserInputDefaultsBehavior.DefaultsNonInteractive
INPUT = common.UserInterfaceMode.InteractionInput
DIALOG = common.UserInterfaceMode.InteractionDialog


@pytest.mark.parametrize('default,expected', [(True, True), (False, False), ('yes', True), ('no', False)])
def test_noninteractive_accept_avoids_both_interfaces(default, expected, monkeypatch):
    monkeypatch.setattr('builtins.input', Mock(side_effect=AssertionError('unexpected interactive call')))
    monkeypatch.setattr(common, 'MainDialog', None)
    assert common.YesOrNo('Continue?', default, ACCEPT | NONINTERACTIVE, uiMode=0) is expected


@pytest.mark.parametrize(
    'reply,expected', [('Y', True), ('YES', True), ('  true ', True), ('n', False), ('No', False), ('0', False)]
)
def test_terminal_understands_valid_replies(reply, expected, monkeypatch):
    monkeypatch.setattr('builtins.input', lambda _: reply)
    assert common.YesOrNo('Continue?', uiMode=INPUT) is expected


def test_input_invalid_values_retry_and_preserve_prompt(monkeypatch):
    prompts = []
    responses = iter(['wrong', ' ', 'yes'])

    def ask(prompt):
        prompts.append(prompt)
        return next(responses)

    monkeypatch.setattr('builtins.input', ask)
    assert common.YesOrNo('Continue?', default=True, uiMode=INPUT) is True
    assert prompts == ['\nContinue? (Y / n): '] * 3


@pytest.mark.parametrize(
    'default,expect_label',
    [
        (True, '(Y / n)'),
        (False, '(y / N)'),
        (None, '(Y / N)'),
    ],
)
def test_default_prompt_capitalization(default, expect_label, monkeypatch):
    questions = []

    def ask(prompt):
        questions.append(prompt)
        return 'y'

    monkeypatch.setattr('builtins.input', ask)
    assert common.YesOrNo('Proceed?', default=default, defaultBehavior=PROMPT, uiMode=INPUT)
    assert expect_label in questions[0]


def test_custom_prompt_labels_and_default_acceptance(monkeypatch):
    received = []
    monkeypatch.setattr('builtins.input', lambda prompt: received.append(prompt) or '')
    assert (
        common.YesOrNo(
            'Go?', default=False, defaultBehavior=PROMPT | ACCEPT, uiMode=INPUT, yesLabel='Proceed', noLabel='Decline'
        )
        is False
    )
    assert received == ['\nGo? (y (Proceed) / N (Decline)): ']


def test_default_true_accepts_empty_reply(monkeypatch):
    monkeypatch.setattr('builtins.input', lambda _: '')
    assert common.YesOrNo('Go?', default=True, defaultBehavior=ACCEPT | PROMPT, uiMode=INPUT) is True


def test_empty_without_acceptance_retries(monkeypatch):
    responses = iter(['', 'n'])
    monkeypatch.setattr('builtins.input', lambda _: next(responses))
    assert common.YesOrNo('Go?', default=True, defaultBehavior=PROMPT, uiMode=INPUT) is False


def test_extra_choice_raises_back(monkeypatch):
    monkeypatch.setattr('builtins.input', lambda _: 'back')
    with pytest.raises(common.DialogBackException):
        common.YesOrNo('Go?', uiMode=INPUT, extraLabel='Previous')


def test_clear_screen_after_terminal_choice(monkeypatch):
    cleared = Mock()
    monkeypatch.setattr(common, 'ClearScreen', cleared)
    monkeypatch.setattr('builtins.input', lambda _: 'yes')
    assert common.YesOrNo('Go?', clearScreen=True, uiMode=INPUT) is True
    cleared.assert_called_once_with()


@pytest.fixture
def fake_dialog(monkeypatch):
    codes = SimpleNamespace(OK=0, CANCEL=1, EXTRA=3, ESC=255)
    dialog = SimpleNamespace(yesno=Mock(return_value=0))
    monkeypatch.setattr(common, 'Dialog', codes)
    monkeypatch.setattr(common, 'MainDialog', dialog)
    monkeypatch.setattr(common, '_dialog_size_for', lambda _: (15, 72))
    return codes, dialog


@pytest.mark.parametrize(
    'default,reply,expected',
    [
        (True, 0, True),
        (True, 1, False),
        (False, 0, False),
        (False, 1, True),
        (None, 0, False),
        (None, 1, True),
    ],
)
def test_dialog_default_button_mapping(fake_dialog, default, reply, expected):
    codes, dialog = fake_dialog
    dialog.yesno.return_value = reply
    assert common.YesOrNo('Proceed?', default=default, uiMode=DIALOG) is expected
    _, kwargs = dialog.yesno.call_args
    assert kwargs['height'] == 15
    assert kwargs['width'] == 72
    assert kwargs['extra_button'] is False


def test_dialog_extra_label_uses_existing_button_swap(fake_dialog):
    codes, dialog = fake_dialog
    for reply, result in [(codes.OK, False), (codes.EXTRA, True)]:
        dialog.yesno.return_value = reply
        assert common.YesOrNo('Proceed?', default=False, uiMode=DIALOG, extraLabel='Back') is result
    assert dialog.yesno.call_args.kwargs['no_label'] == 'Back'
    dialog.yesno.return_value = codes.CANCEL
    with pytest.raises(common.DialogBackException):
        common.YesOrNo('Proceed?', default=False, uiMode=DIALOG, extraLabel='Back')


def test_dialog_extra_no_default_true(fake_dialog):
    codes, dialog = fake_dialog
    dialog.yesno.return_value = codes.CANCEL
    with pytest.raises(common.DialogBackException):
        common.YesOrNo('Proceed?', default=True, uiMode=DIALOG, extraLabel='Back')


def test_no_ui_without_explicit_noninteractive_default():
    with pytest.raises(RuntimeError, match='No user interfaces'):
        common.YesOrNo('Proceed?', uiMode=0)
