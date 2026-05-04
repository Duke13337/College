"""Тесты вспомогательных функций для списка заявок (без БД)."""

import main


class _QP:
    def __init__(self, d: dict):
        self._d = d

    def get(self, k, default=None):
        return self._d.get(k, default)


def test_sanitize_bookings_return_qs_strips_unknown_and_keeps_filters():
    s = main.sanitize_bookings_return_qs("status=pending&evil=1&college_id=5")
    assert "evil" not in s
    assert "status=pending" in s
    assert "college_id=5" in s


def test_sanitize_bookings_return_qs_page_only_from_two():
    assert main.sanitize_bookings_return_qs("page=1") == ""
    s = main.sanitize_bookings_return_qs("page=4&status=confirmed")
    assert "page=4" in s
    assert "status=confirmed" in s


def test_bookings_redirect_url_merges_notice():
    url = main.bookings_redirect_url("status=pending", notice="confirmed")
    assert url.startswith("/bookings?")
    assert "status=pending" in url
    assert "notice=confirmed" in url


def test_bookings_list_url_page_one_omitted():
    qp = _QP({"status": "pending"})
    assert main.bookings_list_url(qp, 1) == "/bookings?status=pending"
    u = main.bookings_list_url(qp, 2)
    assert "status=pending" in u
    assert "page=2" in u


def test_bookings_export_qs_ignores_page():
    qp = _QP({"status": "pending", "page": "3"})
    assert main.bookings_export_qs_from_request(qp) == "status=pending"


def test_bookings_filter_qs_includes_page_when_gt_one():
    qp = _QP({"status": "pending", "page": "2"})
    s = main.bookings_filter_qs_from_request(qp)
    assert "status=pending" in s
    assert "page=2" in s
