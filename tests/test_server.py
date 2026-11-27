import httpx2
import pytest
from conftest import APPROVAL_KEY, call, session

from internal_mcp.approvals import Approvals

GOOD_AD = {
    "template_id": "meta-feed-1x1",
    "headline": "Bookkeeping that keeps up",
    "body": "Send invoices and see cash flow in one place.",
    "cta": "Start free trial",
    "legal_line": "Terms apply. See ledgerly.example/terms.",
    "colours": ["#0B1F33", "#2CA01C"],
}


async def test_no_token_is_turned_away_at_the_door(live):
    async with httpx2.AsyncClient() as http:
        r = await http.post(live.url, json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
    assert r.status_code == 401
    assert "www-authenticate" in r.headers


async def test_a_forged_token_is_turned_away(live):
    forged = live.token("brand:read")[:-4] + "AAAA"
    with pytest.raises(Exception):  # noqa: B017 - the client surfaces the 401 as a transport error
        async with session(live.url, forged):
            pass


async def test_brand_tools_work_with_brand_scope(live):
    ok, tpl = await call(live.url, live.token("brand:read"), "get_template", template_id="google-rsa")
    assert ok and tpl["slots"]["headline"]["max_chars"] == 30
    ok, qa = await call(live.url, live.token("brand:read"), "check_ad", **GOOD_AD)
    assert ok and qa == {"passed": True, "failures": []}


async def test_scopes_are_enforced_per_tool(live):
    ok, err = await call(live.url, live.token("brand:read"), "find_accounts", query="Halden")
    assert not ok and "needs the 'crm:read' scope" in err
    ok, rows = await call(live.url, live.token("crm:read"), "find_accounts", query="Halden")
    assert ok and rows[0]["id"] == "ACC-1002"


async def test_brand_qa_catches_hard_rule_breaks(live):
    bad = {
        **GOOD_AD,
        "headline": "Guaranteed savings, instant results for every business",
        "cta": "Buy now",
        "legal_line": "T&Cs",
        "colours": ["#FF0000"],
    }
    ok, qa = await call(live.url, live.token("brand:read"), "check_ad", **bad)
    rules = {f["rule"] for f in qa["failures"]}
    assert ok and not qa["passed"]
    assert {"headline_length", "banned_word", "cta", "legal_line", "colour"} <= rules


@pytest.mark.parametrize(
    "query",
    ["' OR '1'='1", "%", "_", "Halden'; DROP TABLE accounts; --", "x" * 200, ""],
)
async def test_crm_search_treats_input_as_data(live, query):
    ok, out = await call(live.url, live.token("crm:read"), "find_accounts", query=query)
    if ok:
        assert out == []  # wildcards and quotes are literal, so nothing matches
    else:
        assert "query must be" in out


@pytest.mark.parametrize("account_id", ["ACC-1002' OR 1=1--", "../../etc/passwd", "ACC-1"])
async def test_account_ids_are_validated(live, account_id):
    ok, out = await call(live.url, live.token("crm:read"), "list_campaigns", account_id=account_id)
    assert not ok and "must look like ACC-1234" in out


async def test_write_needs_scope_qa_and_a_matching_one_time_approval(live):
    draft = {"account_id": "ACC-1002", **GOOD_AD}
    approver = Approvals(APPROVAL_KEY)
    token_rw = live.token("brand:read", "drafts:write")

    ok, err = await call(live.url, live.token("brand:read"), "save_ad_draft", **draft, approval_token="x")
    assert not ok and "drafts:write" in err

    ok, err = await call(live.url, token_rw, "save_ad_draft", **draft, approval_token="not-a-token")
    assert not ok and "malformed" in err

    approval = approver.issue(draft, approver="finance-lead")
    edited = {**draft, "headline": "Bookkeeping that keeps up!"}
    ok, err = await call(live.url, token_rw, "save_ad_draft", **edited, approval_token=approval)
    assert not ok and "different draft" in err

    ok, out = await call(live.url, token_rw, "save_ad_draft", **draft, approval_token=approval)
    assert ok and out["approved_by"] == "finance-lead"

    ok, err = await call(live.url, token_rw, "save_ad_draft", **draft, approval_token=approval)
    assert not ok and "already been used" in err

    forged = Approvals("z" * 40).issue(draft, approver="me")
    ok, err = await call(live.url, token_rw, "save_ad_draft", **draft, approval_token=forged)
    assert not ok and "signature is invalid" in err


async def test_a_draft_that_fails_qa_cannot_be_saved_even_if_approved(live):
    draft = {"account_id": "ACC-1002", **GOOD_AD, "cta": "Buy now"}
    approval = Approvals(APPROVAL_KEY).issue(draft, approver="finance-lead")
    ok, err = await call(
        live.url, live.token("drafts:write"), "save_ad_draft", **draft, approval_token=approval
    )
    assert not ok and "fails brand QA" in err


async def test_unknown_accounts_cannot_receive_drafts(live):
    draft = {"account_id": "ACC-9999", **GOOD_AD}
    ok, err = await call(live.url, live.token("drafts:write"), "save_ad_draft", **draft, approval_token="x")
    assert not ok and "unknown account_id" in err


async def test_oversized_text_is_refused(live):
    ok, err = await call(live.url, live.token("brand:read"), "check_ad", **{**GOOD_AD, "body": "x" * 5000})
    assert not ok and "longer than" in err


async def test_the_audit_log_records_outcomes_without_arguments(live):
    await call(live.url, live.token("brand:read", client="auditee"), "find_accounts", query="secret-name")
    rows = [r for r in live.audit.read() if r["client"] == "auditee"]
    assert rows[-1]["outcome"] == "denied_scope" and rows[-1]["needed"] == "crm:read"
    assert "secret-name" not in live.audit.path.read_text(encoding="utf-8")


async def test_internal_errors_do_not_leak_to_the_agent(live):
    ok, err = await call(live.url, live.token("brand:read"), "get_template", template_id="x" * 41)
    assert not ok and "unknown template_id" in err and "Traceback" not in err
