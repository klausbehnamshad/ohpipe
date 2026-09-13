import io

from ohpipe.cli.finalisation import _resolution_answer
from ohpipe.cli.main import _b3b_choice
from ohpipe.cli.manual import _action, _session_choice
from ohpipe.cli.ui import confirmed, confirmation_word, is_english, text
from ohpipe.policies.exit_contract import Report, Status


def test_german_interactive_ui_remains_the_default(monkeypatch):
    monkeypatch.delenv("OHPIPE_UI_LANG", raising=False)

    assert not is_english()
    assert text("Deutsch", "English") == "Deutsch"
    assert confirmation_word() == "BESTÄTIGEN"
    assert confirmed("BESTÄTIGEN")
    assert _b3b_choice() == "[b] Bestaetigen / [a] Abbrechen"


def test_english_interactive_ui_uses_clear_operator_words(monkeypatch):
    monkeypatch.setenv("OHPIPE_UI_LANG", "en")

    assert is_english()
    assert text("Deutsch", "English") == "English"
    assert confirmation_word() == "CONFIRM"
    assert confirmed("CONFIRM")
    assert not confirmed("BESTÄTIGEN")
    assert _b3b_choice() == "[c] Confirm / [a] Abort"
    assert _session_choice("new") == "neu"
    assert _session_choice("resume") == "fortsetzen"
    assert _action("mark") == "markieren"
    assert _action("confirm") == "bestätigen"
    assert _action("defer") == "zurückstellen"
    assert _resolution_answer("new") == "neu"
    assert _resolution_answer("close") == "schließen"


def test_english_locale_variants_enable_the_english_ui(monkeypatch):
    monkeypatch.setenv("OHPIPE_UI_LANG", "en_GB.UTF-8")

    assert is_english()


def test_english_report_keeps_stable_fields_and_translates_operator_values(monkeypatch):
    monkeypatch.setenv("OHPIPE_UI_LANG", "en")
    output = io.StringIO()

    Report(status=Status.READY).render(output, color=False)

    assert output.getvalue().splitlines() == [
        "STATUS : READY",
        "CHANGED: none",
        "SAFE   : Source data unchanged; Upload no",
        "NEXT   : —",
        "CHECK  : —",
        "RECOVERY: —",
    ]
