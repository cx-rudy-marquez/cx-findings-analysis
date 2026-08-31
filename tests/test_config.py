"""The REONBOARD flag.

Re-onboarding is the one flow that moves a live repository from one project to
another, so the default matters more than the feature: absent must mean off, and
anything that is not an affirmative must mean off too.
"""

import pytest

from config import Settings


@pytest.fixture(autouse=True)
def clean_env(monkeypatch):
    """Neither spelling set, whatever the developer's own .env says."""
    monkeypatch.delenv("REONBOARD", raising=False)
    monkeypatch.delenv("reonboard", raising=False)


def test_an_absent_flag_means_off():
    assert Settings.from_env().reonboard_enabled is False


def test_the_documented_upper_case_name_enables_it(monkeypatch):
    monkeypatch.setenv("REONBOARD", "true")
    assert Settings.from_env().reonboard_enabled is True


def test_the_lower_case_name_from_the_goal_doc_also_works(monkeypatch):
    """Accepted so an .env written by hand against the spec still works."""
    monkeypatch.setenv("reonboard", "true")
    assert Settings.from_env().reonboard_enabled is True


def test_either_name_alone_is_enough(monkeypatch):
    monkeypatch.setenv("REONBOARD", "false")
    monkeypatch.setenv("reonboard", "true")
    assert Settings.from_env().reonboard_enabled is True


def test_the_usual_affirmatives_all_work(monkeypatch):
    for raw in ("1", "true", "TRUE", "yes", "on", " true "):
        monkeypatch.setenv("REONBOARD", raw)
        assert Settings.from_env().reonboard_enabled is True, raw


def test_anything_that_is_not_an_affirmative_is_off(monkeypatch):
    """Including nonsense: an unreadable value must not enable the flow."""
    for raw in ("false", "0", "no", "off", "", "maybe", "TRUEISH"):
        monkeypatch.setenv("REONBOARD", raw)
        assert Settings.from_env().reonboard_enabled is False, raw


def test_the_flag_does_not_disturb_the_rest_of_the_configuration(monkeypatch):
    monkeypatch.setenv("REONBOARD", "true")
    settings = Settings.from_env()
    assert settings.reonboard_enabled is True
    assert "reonboard" not in settings.describe()
