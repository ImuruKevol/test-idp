import datetime
import importlib.util
from pathlib import Path
from types import SimpleNamespace


ROOT = Path(__file__).resolve().parents[1]


def load_process():
    path = ROOT / "src/portal/samlidp/model/struct/process.py"
    spec = importlib.util.spec_from_file_location("saml_console_process", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class FakeCreatedField:
    def __ge__(self, value):
        return ("created_at_or_after", value)


class FakeQuery:
    def __init__(self):
        self.expression = None

    def where(self, expression):
        self.expression = expression
        return self


class FakeTransactionDb:
    def __init__(self, total=0):
        self.total = total
        self.row_calls = []
        self.count_calls = []
        self.expressions = []

    def _apply_query(self, kwargs):
        callback = kwargs.get("query")
        if callback is None:
            return
        query = callback(SimpleNamespace(created=FakeCreatedField()), FakeQuery())
        self.expressions.append(query.expression)

    def rows(self, **kwargs):
        self.row_calls.append(kwargs)
        self._apply_query(kwargs)
        return []

    def count(self, **kwargs):
        self.count_calls.append(kwargs)
        self._apply_query(kwargs)
        return self.total


def test_transaction_history_is_newest_first_and_capped():
    module = load_process()
    db = FakeTransactionDb()
    process = module.Process(SimpleNamespace(db=lambda name: db))

    process.list_transactions(limit=50)

    call = db.row_calls[0]
    assert call["orderby"] == "created"
    assert call["order"] == "DESC"
    assert call["page"] == 1
    assert call["dump"] == 50


def test_active_session_summary_uses_eight_hour_window_and_display_cap():
    module = load_process()
    db = FakeTransactionDb(total=7)
    process = module.Process(SimpleNamespace(
        db=lambda name: db,
        core=SimpleNamespace(user=SimpleNamespace(get=lambda **kwargs: None)),
    ))
    before = datetime.datetime.now() - datetime.timedelta(hours=8, seconds=1)

    summary = process.active_session_summary(limit=500)

    assert summary == {"items": [], "total": 7, "window_hours": 8, "limit": 50}
    row_call = db.row_calls[0]
    assert row_call["page"] == 1
    assert row_call["dump"] == 50
    assert row_call["order"] == "DESC"
    assert db.expressions
    assert all(expression[0] == "created_at_or_after" for expression in db.expressions)
    assert all(expression[1] >= before for expression in db.expressions)
