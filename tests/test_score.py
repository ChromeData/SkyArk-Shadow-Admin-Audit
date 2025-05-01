"""Offline tests for the scoring core.

No SkyArk, no cloud, no network. The matching and classification logic is what
the whole finding rests on - if `match` is wrong, a real catch reads as a miss
and the tool looks broken. These pin that behaviour.

Run:  python -m pytest tests/ -v
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

from score import match, classify  # noqa: E402


def planted(*names):
    return [{"principal": n, "technique": "x"} for n in names]


# Realistic principal names. Single characters would collide under substring
# matching ("a" is inside "mystery-admin"), which is a genuine limitation of the
# approach but never occurs with real lab-shadow-* names.
A = "lab-shadow-passrole"
B = "lab-shadow-attach"
C = "lab-shadow-assumer"


class TestMatch:
    def test_exact(self):
        assert match("lab-shadow-passrole", {"lab-shadow-passrole"})

    def test_skyark_decorates_with_type(self):
        # "lab-shadow-passrole (IAM User)" must still count as caught.
        assert match("lab-shadow-passrole", {"lab-shadow-passrole (IAM User)"})

    def test_skyark_reports_full_arn(self):
        assert match(
            "lab-shadow-attach",
            {"arn:aws:iam::123456789012:user/lab-shadow-attach"},
        )

    def test_unrelated_is_not_a_match(self):
        assert not match("lab-shadow-passrole", {"some-other-user"})

    def test_empty_scan_never_matches(self):
        assert not match("lab-shadow-passrole", set())


class TestClassify:
    def test_all_caught(self):
        p = planted(A, B)
        caught, missed, extra = classify(p, {A, B})
        assert len(caught) == 2 and not missed and not extra

    def test_a_miss_is_the_headline(self):
        # This is the result worth writing about: planted but not flagged.
        p = planted(A, B)
        caught, missed, extra = classify(p, {A})
        assert [m["principal"] for m in missed] == [B]

    def test_false_positive_is_surfaced(self):
        p = planted(A)
        caught, missed, extra = classify(p, {A, "mystery-admin-role"})
        assert extra == ["mystery-admin-role"]

    def test_nothing_flagged_means_everything_missed(self):
        p = planted(A, B, C)
        caught, missed, extra = classify(p, set())
        assert len(missed) == 3 and not caught
