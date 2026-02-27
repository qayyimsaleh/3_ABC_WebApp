#!/usr/bin/env python3
"""
ABC WebApp Security Test Suite
================================
Tests your OWN application for the vulnerabilities identified in the audit.
Run this against your intranet server ONLY — do not use against systems you
don't own or have explicit permission to test.

Usage:
    pip install requests colorama
    python abc_security_tester.py --url https://ioipcnintranet/ABC_NET --emp E1880 --ic 5743

    # If your IIS uses Windows Authentication:
    python abc_security_tester.py --url https://ioipcnintranet/ABC_NET --emp E1880 --ic 5743 --windows-auth
"""

import argparse
import sys
import time
import re
import requests
import requests.auth
import urllib3
from colorama import Fore, Style, init

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
init(autoreset=True)

PASS = f"{Fore.GREEN}[PASS]{Style.RESET_ALL}"
FAIL = f"{Fore.RED}[FAIL]{Style.RESET_ALL}"
WARN = f"{Fore.YELLOW}[WARN]{Style.RESET_ALL}"
INFO = f"{Fore.CYAN}[INFO]{Style.RESET_ALL}"
HEAD = f"{Fore.MAGENTA}"

results = []
WIN_AUTH = False   # set to True via --windows-auth flag


def log(status, test_name, detail=""):
    symbol = {"PASS": PASS, "FAIL": FAIL, "WARN": WARN, "INFO": INFO}.get(status, INFO)
    print(f"  {symbol} {test_name}")
    if detail:
        print(f"         {Fore.WHITE}{detail}{Style.RESET_ALL}")
    results.append({"status": status, "test": test_name, "detail": detail})


def section(title):
    print(f"\n{HEAD}{'─'*60}")
    print(f"  {title}")
    print(f"{'─'*60}{Style.RESET_ALL}")


def make_session():
    """Create a requests session with optional Windows Auth."""
    s = requests.Session()
    if WIN_AUTH:
        try:
            from requests_ntlm import HttpNtlmAuth
            import getpass, os
            user = os.environ.get("USERNAME", getpass.getuser())
            domain = os.environ.get("USERDOMAIN", "")
            s.auth = HttpNtlmAuth(f"{domain}\\{user}", "")
            log("INFO", f"Windows Auth enabled as {domain}\\{user}")
        except ImportError:
            # Fall back to negotiate without requests_ntlm
            s.auth = requests.auth.HTTPBasicAuth("", "")
    return s


def get(session, url, **kwargs):
    return session.get(url, verify=False, timeout=15, **kwargs)


def post(session, url, **kwargs):
    return session.post(url, verify=False, timeout=15, **kwargs)


def get_csrf_token(session, url):
    """Extract antiforgery token — handles 401 by checking WWW-Authenticate."""
    try:
        r = get(session, url, allow_redirects=True)
        if r.status_code == 401:
            auth_type = r.headers.get("WWW-Authenticate", "")
            log("WARN", "Server requires IIS-level authentication before app loads",
                f"WWW-Authenticate: {auth_type or 'present'} — run with --windows-auth if on domain machine")
            return None
        match = re.search(
            r'<input[^>]+name="__RequestVerificationToken"[^>]+value="([^"]+)"', r.text)
        return match.group(1) if match else None
    except Exception as e:
        log("WARN", f"Could not reach login page: {e}")
        return None


def app_login(base_url, emp, ic):
    """Login to the MVC app and return authenticated session + bool success."""
    login_url = f"{base_url}/Auth/Login"
    session = make_session()
    token = get_csrf_token(session, login_url)
    if not token:
        return session, False

    r = post(session, login_url, data={
        "__RequestVerificationToken": token,
        "Username": emp,
        "Password": ic
    }, allow_redirects=True)

    success = ("/Home/Index" in r.url or "Training" in r.text
               or "Dashboard" in r.text or "logout" in r.text.lower())
    return session, success


# ─────────────────────────────────────────────
# TESTS
# ─────────────────────────────────────────────

def test_security_headers(base_url):
    section("1. HTTP SECURITY HEADERS")
    session = make_session()
    r = get(session, base_url, allow_redirects=True)

    if r.status_code == 401:
        log("WARN", "Got 401 — IIS auth blocks header inspection at root",
            "Try browsing to login page directly to verify headers in browser DevTools")
        # Try the login page specifically
        r = get(session, f"{base_url}/Auth/Login", allow_redirects=True)
        if r.status_code == 401:
            log("WARN", "Cannot inspect headers — all pages require IIS authentication")
            return

    headers = {k.lower(): v for k, v in r.headers.items()}

    checks = [
        ("x-frame-options",        "Clickjacking protection (X-Frame-Options)"),
        ("x-content-type-options", "MIME sniffing protection (X-Content-Type-Options)"),
        ("x-xss-protection",       "XSS filter header (X-XSS-Protection)"),
        ("referrer-policy",        "Referrer leakage protection (Referrer-Policy)"),
    ]
    for header, label in checks:
        if header in headers:
            log("PASS", label, f"Value: {headers[header]}")
        else:
            log("FAIL", label, f"Header '{header}' is missing from response")

    # Server version — ':)' is still a Server header, should be removed entirely
    server = headers.get("server", "")
    if not server:
        log("PASS", "Server header not present")
    elif server in (":)", ""):
        log("WARN", "Server header has custom value but is still present",
            f"Value: '{server}' — remove it entirely in IIS: HTTP Response Headers → Remove 'Server'")
    else:
        log("FAIL", "Server version disclosed", f"Value: '{server}'")

    xpow = headers.get("x-powered-by", "")
    if xpow:
        log("FAIL", "X-Powered-By header present", f"Value: '{xpow}'")
    else:
        log("PASS", "X-Powered-By removed")

    # HTTPS redirect check
    http_url = base_url.replace("https://", "http://")
    try:
        r2 = get(make_session(), http_url, allow_redirects=False)
        if r2.status_code in (301, 302) and "https" in r2.headers.get("location", "").lower():
            log("PASS", "HTTP redirects to HTTPS")
        else:
            log("WARN", "HTTP does not redirect to HTTPS", f"Status: {r2.status_code}")
    except Exception:
        log("INFO", "HTTP redirect check skipped (port 80 not reachable)")


def test_authentication(base_url, valid_emp, valid_ic):
    section("2. AUTHENTICATION & BRUTE FORCE")
    login_url = f"{base_url}/Auth/Login"
    session = make_session()

    token = get_csrf_token(session, login_url)
    if not token:
        log("WARN", "Skipping auth tests — cannot reach login page (IIS auth in the way?)")
        log("INFO", "These tests need the MVC app login page to be reachable unauthenticated")
        return session

    # Valid login
    r = post(session, login_url, data={
        "__RequestVerificationToken": token,
        "Username": valid_emp,
        "Password": valid_ic
    }, allow_redirects=True)
    if "/Home/Index" in r.url or "Training" in r.text or "logout" in r.text.lower():
        log("PASS", "Valid credentials authenticate successfully")
    else:
        log("FAIL", "Valid credentials did NOT authenticate — check --emp and --ic values",
            f"Final URL: {r.url}")

    get(session, f"{base_url}/Auth/Logout", allow_redirects=True)

    # Wrong password
    token = get_csrf_token(session, login_url)
    r = post(session, login_url, data={
        "__RequestVerificationToken": token or "",
        "Username": valid_emp,
        "Password": "WRONGPASSWORD99999"
    })
    if r.status_code == 200 and "/Home" not in r.url:
        log("PASS", "Wrong password correctly rejected")
    else:
        log("FAIL", "Wrong password was NOT rejected!")

    # Brute force delay
    times = []
    for i in range(3):
        token = get_csrf_token(session, login_url)
        start = time.time()
        post(session, login_url, data={
            "__RequestVerificationToken": token or "",
            "Username": valid_emp,
            "Password": f"WRONGPW_{i}"
        })
        times.append(time.time() - start)

    avg = sum(times) / len(times)
    if avg >= 1.0:
        log("PASS", "Brute force delay active", f"Avg time on failed login: {avg:.2f}s")
    else:
        log("FAIL", "No brute force delay detected",
            f"Avg time: {avg:.2f}s — Thread.Sleep(1500) should give ≥1.5s")

    # Non-existent employee
    token = get_csrf_token(session, login_url)
    r = post(session, login_url, data={
        "__RequestVerificationToken": token or "",
        "Username": "XXXXNOTREAL9999",
        "Password": "anything"
    }, allow_redirects=True)
    if "/Home" not in r.url:
        log("PASS", "Non-existent employee correctly rejected")
    else:
        log("FAIL", "Non-existent employee was authenticated!")

    return session


def test_csrf(base_url, valid_emp, valid_ic):
    section("3. CSRF PROTECTION")
    login_url = f"{base_url}/Auth/Login"
    session, ok = app_login(base_url, valid_emp, valid_ic)

    if not ok:
        log("WARN", "Skipping CSRF tests — could not log in to app")
        log("INFO", "If IIS Windows Auth is on, CSRF tokens may not be testable via script")
        return

    # Test admin POSTs without CSRF token — should be rejected with 400/500
    endpoints = [
        ("ToggleActive",   {"empID": valid_emp}),
        ("DeleteEmployee", {"empID": "FAKEDEL999"}),
        ("SaveEmployee",   {"EmployeeID": "FAKE999", "UserName": "Hacker"}),
    ]
    for action, data in endpoints:
        r = post(session, f"{base_url}/Admin/{action}", data=data)
        if r.status_code in (400, 403, 500):
            log("PASS", f"CSRF blocked on /Admin/{action}", f"Status: {r.status_code}")
        elif r.status_code == 302:
            log("PASS", f"CSRF rejected (redirect) on /Admin/{action}")
        else:
            try:
                j = r.json()
                if not j.get("success", True):
                    log("PASS", f"CSRF rejected on /Admin/{action}", j.get("message", ""))
                else:
                    log("FAIL", f"CSRF NOT blocked on /Admin/{action}!",
                        f"Response: {r.text[:120]}")
            except Exception:
                log("WARN", f"CSRF result inconclusive on /Admin/{action}",
                    f"Status: {r.status_code} — manually verify [ValidateAntiForgeryToken] is present")

    # Login without CSRF token
    r = post(make_session(), login_url, data={
        "Username": valid_emp,
        "Password": valid_ic
    })
    if r.status_code in (400, 403, 500) or "AntiForgery" in r.text:
        log("PASS", "CSRF blocked on /Auth/Login (no token → rejected)")
    elif r.status_code == 200 and "/Home" not in r.url:
        log("PASS", "Login without CSRF token did not authenticate")
    else:
        log("FAIL", "Login may not be CSRF-protected", f"Status: {r.status_code}")


def test_user_enumeration(base_url, valid_emp):
    section("4. USER ENUMERATION (LookupEmployee)")
    session, ok = app_login(base_url, *["", ""])  # public endpoint, no login needed
    session = make_session()

    r = get(session, f"{base_url}/Auth/LookupEmployee", params={"id": valid_emp})
    if r.status_code == 401:
        log("WARN", "LookupEmployee returns 401 — IIS auth is blocking it",
            "This actually IMPROVES security — external users can't enumerate employees")
        log("PASS", "Employee enumeration not possible from outside IIS auth boundary")
        return
    if r.status_code != 200:
        log("WARN", f"LookupEmployee returned {r.status_code}")
        return

    try:
        j = r.json()
        if j.get("found"):
            fields = [k for k in j.keys() if k != "found"]
            if "department" in fields:
                log("FAIL", "LookupEmployee exposes department", f"Fields: {fields}")
            else:
                log("PASS", "Department not exposed in LookupEmployee")
            if "name" in fields:
                log("WARN", "LookupEmployee exposes employee name",
                    "Low risk on intranet but consider removing for minimal exposure")
            else:
                log("PASS", "Employee name not exposed in LookupEmployee")
        else:
            log("WARN", "LookupEmployee returned not-found for valid ID — check --emp value")
    except Exception:
        log("WARN", "LookupEmployee returned non-JSON", f"Body: {r.text[:100]}")

    # Timing check
    times_miss, times_hit = [], []
    for fid in ["XXXXFAKE001", "XXXXFAKE002", "XXXXFAKE003"]:
        s = time.time()
        get(session, f"{base_url}/Auth/LookupEmployee", params={"id": fid})
        times_miss.append(time.time() - s)
    for _ in range(3):
        s = time.time()
        get(session, f"{base_url}/Auth/LookupEmployee", params={"id": valid_emp})
        times_hit.append(time.time() - s)
    diff = abs(sum(times_hit)/3 - sum(times_miss)/3)
    if diff < 0.3:
        log("PASS", "No timing oracle — found/not-found response times similar",
            f"Diff: {diff:.3f}s")
    else:
        log("WARN", "Timing difference may reveal valid IDs", f"Diff: {diff:.3f}s")


def test_authorization(base_url, valid_emp, valid_ic):
    section("5. AUTHORIZATION & ACCESS CONTROL")
    session = make_session()

    # Unauthenticated access
    protected = ["/Home/Index", "/Training/Part1", "/Training/Part2", "/Admin/Dashboard"]
    for path in protected:
        r = get(session, f"{base_url}{path}", allow_redirects=True)
        if "/Auth/Login" in r.url or r.status_code in (401, 403):
            log("PASS", f"Unauthenticated access blocked: {path}")
        else:
            log("FAIL", f"Unauthenticated access ALLOWED: {path}",
                f"Status: {r.status_code}, URL: {r.url}")

    # Authenticated non-admin
    auth_session, ok = app_login(base_url, valid_emp, valid_ic)
    if not ok:
        log("WARN", "Could not log in — skipping authenticated authorization checks")
        return

    admin_endpoints = ["/Admin/Dashboard", "/Admin/GetScoresJson", "/Admin/GetEmployeesJson"]
    for path in admin_endpoints:
        r = get(auth_session, f"{base_url}{path}", allow_redirects=True)
        if r.status_code in (401, 403) or "/Home" in r.url or "/Auth" in r.url:
            log("PASS", f"Non-admin correctly blocked from: {path}")
        elif r.status_code == 200:
            try:
                j = r.json()
                if "error" in j:
                    log("PASS", f"Admin endpoint returned error for non-admin: {path}",
                        f"Error: {j['error']}")
                else:
                    log("WARN", f"Admin endpoint returned data: {path}",
                        "OK if your test account IS an admin — verify with a non-admin account")
            except Exception:
                log("WARN", f"Admin page returned 200: {path}",
                    "OK if test account is admin — re-run with a non-admin employee")


def test_sql_injection(base_url, valid_emp, valid_ic):
    section("6. SQL INJECTION")
    login_url = f"{base_url}/Auth/Login"
    session = make_session()
    token = get_csrf_token(session, login_url)
    if not token:
        log("WARN", "Cannot test SQL injection — login page not reachable unauthenticated")
        return

    payloads = [
        ("' OR '1'='1",                  "Classic OR bypass"),
        ("' OR 1=1 --",                  "Comment bypass"),
        ("admin'--",                      "Admin comment bypass"),
        ("' UNION SELECT NULL,NULL--",    "UNION probe"),
        ("'; DROP TABLE empMaster_lists--", "DROP TABLE"),
        ("1' AND SLEEP(3)--",             "Time-based blind"),
    ]
    for payload, label in payloads:
        token = get_csrf_token(session, login_url)
        start = time.time()
        r = post(session, login_url, data={
            "__RequestVerificationToken": token or "",
            "Username": payload,
            "Password": payload
        }, allow_redirects=True)
        elapsed = time.time() - start
        if "/Home" in r.url or ("logout" in r.text.lower() and "training" in r.text.lower()):
            log("FAIL", f"SQL injection may have succeeded: {label}", f"Payload: {payload}")
        elif elapsed >= 3.0:
            log("FAIL", f"Possible time-based SQL injection: {label}",
                f"Response took {elapsed:.1f}s — server may be executing SLEEP()")
        else:
            log("PASS", f"Blocked: {label}")

    # LookupEmployee SQLi
    session2 = make_session()
    for payload in ["' OR '1'='1", "E001' --", "1; EXEC xp_cmdshell('dir')--"]:
        r = get(session2, f"{base_url}/Auth/LookupEmployee", params={"id": payload})
        if r.status_code == 500:
            log("FAIL", "SQL error on LookupEmployee", f"Payload: {payload}")
        elif r.status_code == 401:
            log("INFO", "LookupEmployee blocked by IIS auth — cannot test SQLi here")
            break
        else:
            log("PASS", f"LookupEmployee handled safely: {payload[:35]}")


def test_xss(base_url):
    section("7. XSS (CROSS-SITE SCRIPTING)")
    login_url = f"{base_url}/Auth/Login"
    session = make_session()
    token = get_csrf_token(session, login_url)
    if not token:
        log("WARN", "Cannot test XSS reflection — login page not reachable unauthenticated")
        return

    payloads = [
        "<script>alert(1)</script>",
        "<img src=x onerror=alert(1)>",
        "'><svg onload=alert(1)>",
        "javascript:alert(document.cookie)",
        "<body onload=alert(1)>",
    ]
    for payload in payloads:
        token = get_csrf_token(session, login_url)
        r = post(session, login_url, data={
            "__RequestVerificationToken": token or "",
            "Username": payload,
            "Password": "anything"
        })
        # Raw payload in response = reflected XSS
        if payload in r.text:
            log("FAIL", "XSS payload reflected unescaped!", f"Payload: {payload[:50]}")
        elif re.search(r"(?i)<script>|onerror\s*=|onload\s*=|javascript:", r.text):
            log("WARN", "Possible XSS in response — review manually", f"Payload: {payload[:50]}")
        else:
            log("PASS", f"Correctly escaped: {payload[:45]}")

    # LookupEmployee XSS reflection
    session2 = make_session()
    for payload in ["<script>alert(1)</script>", "<img src=x onerror=alert(1)>"]:
        r = get(session2, f"{base_url}/Auth/LookupEmployee", params={"id": payload})
        if r.status_code == 401:
            log("INFO", "LookupEmployee blocked by IIS auth — XSS reflection not testable externally")
            break
        if payload in r.text:
            log("FAIL", "XSS reflected in LookupEmployee response", f"Payload: {payload[:50]}")
        else:
            log("PASS", f"LookupEmployee escaped XSS payload safely")


def test_session_security(base_url, valid_emp, valid_ic):
    section("8. SESSION SECURITY")
    login_url = f"{base_url}/Auth/Login"
    session = make_session()

    r = get(session, login_url)
    pre_session = session.cookies.get("ASP.NET_SessionId", "")

    _, ok = app_login.__wrapped__(session, base_url, valid_emp, valid_ic) \
        if hasattr(app_login, "__wrapped__") else (None, None)

    # Re-do login manually to track cookie changes
    token = get_csrf_token(session, login_url)
    if token:
        post(session, login_url, data={
            "__RequestVerificationToken": token,
            "Username": valid_emp,
            "Password": valid_ic
        }, allow_redirects=True)
        post_session = session.cookies.get("ASP.NET_SessionId", "")

        if pre_session and post_session and pre_session != post_session:
            log("PASS", "Session ID regenerated after login (session fixation protection)")
        elif not pre_session:
            log("INFO", "No pre-login session ID to compare (IIS may not issue one until app starts)")
        else:
            log("WARN", "Session ID unchanged after login",
                "Minor risk on intranet — Session.Clear() on login prevents session poisoning")

        # Cookie security flags
        for cookie in session.cookies:
            if cookie.name == "ASP.NET_SessionId":
                if cookie.has_nonstandard_attr("HttpOnly") or "httponly" in str(cookie).lower():
                    log("PASS", "Session cookie has HttpOnly flag")
                else:
                    log("FAIL", "Session cookie missing HttpOnly flag — JS can steal it")
                if cookie.secure:
                    log("PASS", "Session cookie has Secure flag (HTTPS only)")
                else:
                    log("WARN", "Session cookie missing Secure flag",
                        "OK for HTTP-only intranet — add if HTTPS is enforced")

        # Session invalidated on logout
        get(session, f"{base_url}/Auth/Logout", allow_redirects=True)
        r2 = get(session, f"{base_url}/Home/Index", allow_redirects=True)
        if "/Auth/Login" in r2.url:
            log("PASS", "Session correctly invalidated after logout")
        else:
            log("FAIL", "Session still valid after logout!", f"URL: {r2.url}")
    else:
        log("WARN", "Skipping session tests — cannot reach login page")


def test_directory_traversal(base_url):
    section("9. PATH TRAVERSAL & SENSITIVE FILE EXPOSURE")
    session = make_session()

    sensitive = [
        ("/Web.config",                    "Web.config"),
        ("/web.config",                    "web.config (lowercase)"),
        ("/.git/config",                   ".git/config"),
        ("/App_Data/",                     "App_Data directory"),
        ("/bin/ABC_WebApp.dll",            "Application DLL"),
        ("/Views/Web.config",             "Views/Web.config"),
        ("/Global.asax",                   "Global.asax"),
        ("/Content/../../../../Web.config","Path traversal to Web.config"),
    ]
    for path, label in sensitive:
        r = get(session, f"{base_url}{path}", allow_redirects=False)
        if r.status_code == 200 and len(r.content) > 200:
            log("FAIL", f"Sensitive file accessible: {label}", f"Size: {len(r.content)} bytes")
        elif r.status_code in (302, 301):
            # Redirect = auth wall in front = actually protected
            loc = r.headers.get("location","")
            if "login" in loc.lower() or "auth" in loc.lower():
                log("PASS", f"Protected by auth redirect: {label}")
            else:
                log("INFO", f"Redirect on {label}", f"→ {loc[:60]}")
        elif r.status_code in (403, 404):
            log("PASS", f"Blocked ({r.status_code}): {label}")
        else:
            log("INFO", f"Status {r.status_code}: {label}")


def test_error_handling(base_url):
    section("10. ERROR HANDLING & INFO DISCLOSURE")
    session = make_session()

    # 404
    r = get(session, f"{base_url}/ThisDoesNotExist99999", allow_redirects=True)
    if r.status_code == 404 or "/Auth/Login" in r.url:
        if "Stack Trace" in r.text or "System." in r.text or "at System" in r.text:
            log("FAIL", "Error page exposes .NET stack trace",
                "Add <customErrors mode='On'/> to Web.config")
        else:
            log("PASS", "Error page does not expose stack trace or internals")
    else:
        log("INFO", f"404 test: status {r.status_code}")

    # 500 via oversized input
    r = get(session, f"{base_url}/Auth/LookupEmployee",
            params={"id": "A" * 5000}, allow_redirects=True)
    if r.status_code == 500:
        if "Stack Trace" in r.text or "System." in r.text:
            log("FAIL", "500 error exposes stack trace",
                "Set <customErrors mode='On'/> in Web.config")
        else:
            log("PASS", "500 handled without exposing internals")
    elif r.status_code in (400, 401, 404) or "/Auth/Login" in r.url:
        log("PASS", f"Oversized input rejected safely (status {r.status_code})")
    else:
        log("INFO", f"Oversized input: status {r.status_code}")


# ─────────────────────────────────────────────
# SUMMARY
# ─────────────────────────────────────────────

def print_summary():
    print(f"\n{HEAD}{'═'*60}")
    print(f"  SECURITY TEST SUMMARY")
    print(f"{'═'*60}{Style.RESET_ALL}\n")

    counts = {}
    failures, warnings = [], []
    for r in results:
        counts[r["status"]] = counts.get(r["status"], 0) + 1
        if r["status"] == "FAIL":
            failures.append(r)
        elif r["status"] == "WARN":
            warnings.append(r)

    print(f"  {Fore.GREEN}PASS: {counts.get('PASS',0):3d}{Style.RESET_ALL}   "
          f"{Fore.RED}FAIL: {counts.get('FAIL',0):3d}{Style.RESET_ALL}   "
          f"{Fore.YELLOW}WARN: {counts.get('WARN',0):3d}{Style.RESET_ALL}   "
          f"{Fore.CYAN}INFO: {counts.get('INFO',0):3d}{Style.RESET_ALL}")

    if failures:
        print(f"\n{Fore.RED}  ── FAILURES (fix immediately) ──{Style.RESET_ALL}")
        for f in failures:
            print(f"  {Fore.RED}✗{Style.RESET_ALL} {f['test']}")
            if f["detail"]:
                print(f"    {Fore.WHITE}{f['detail']}{Style.RESET_ALL}")

    if warnings:
        print(f"\n{Fore.YELLOW}  ── WARNINGS (review recommended) ──{Style.RESET_ALL}")
        for w in warnings:
            print(f"  {Fore.YELLOW}!{Style.RESET_ALL} {w['test']}")
            if w["detail"]:
                print(f"    {Fore.WHITE}{w['detail']}{Style.RESET_ALL}")

    iis_note_shown = any("IIS" in r.get("detail","") or "401" in r.get("detail","")
                         for r in results if r["status"] in ("WARN","INFO"))
    if iis_note_shown:
        print(f"\n{Fore.CYAN}  ── NOTE: IIS Authentication ──{Style.RESET_ALL}")
        print(f"  Many WARN/INFO results are because IIS Windows/Basic Auth")
        print(f"  sits in front of the app — this is actually good security.")
        print(f"  Re-run with --windows-auth on a domain-joined machine for")
        print(f"  full authenticated test coverage.")

    color = Fore.GREEN if counts.get("FAIL", 0) == 0 else Fore.RED
    label = "ALL CHECKS PASSED" if counts.get("FAIL", 0) == 0 else "VULNERABILITIES FOUND"
    print(f"\n  {color}Overall: {label}{Style.RESET_ALL}\n")


# ─────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────

def main():
    global WIN_AUTH
    parser = argparse.ArgumentParser(
        description="ABC WebApp Security Test Suite — your own app only"
    )
    parser.add_argument("--url",          required=True,
                        help="Base URL e.g. https://ioipcnintranet/ABC_NET")
    parser.add_argument("--emp",          required=True,
                        help="Valid Employee ID")
    parser.add_argument("--ic",           required=True,
                        help="IC number (password)")
    parser.add_argument("--windows-auth", action="store_true",
                        help="Use Windows NTLM auth for IIS-level authentication")
    args = parser.parse_args()

    WIN_AUTH = args.windows_auth
    base = args.url.rstrip("/")

    print(f"""
{HEAD}╔══════════════════════════════════════════════════╗
║       ABC WebApp Security Test Suite             ║
║       Target: {base:<35}║
╚══════════════════════════════════════════════════╝{Style.RESET_ALL}
{Fore.YELLOW}  ⚠  Run against YOUR OWN application only.{Style.RESET_ALL}
""")

    try:
        test_security_headers(base)
        test_authentication(base, args.emp, args.ic)
        test_csrf(base, args.emp, args.ic)
        test_user_enumeration(base, args.emp)
        test_authorization(base, args.emp, args.ic)
        test_sql_injection(base, args.emp, args.ic)
        test_xss(base)
        test_session_security(base, args.emp, args.ic)
        test_directory_traversal(base)
        test_error_handling(base)
    except requests.exceptions.ConnectionError:
        print(f"\n{Fore.RED}  ERROR: Cannot connect to {base}")
        print(f"  Make sure the server is reachable from this machine.{Style.RESET_ALL}")
        sys.exit(1)
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}  Interrupted.{Style.RESET_ALL}")

    print_summary()


if __name__ == "__main__":
    main()


import argparse
import sys
import time
import json
import re
import requests
import urllib3
from colorama import Fore, Style, init

# Suppress SSL warnings for internal intranet certs
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
init(autoreset=True)

# ─────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────

PASS  = f"{Fore.GREEN}[PASS]{Style.RESET_ALL}"
FAIL  = f"{Fore.RED}[FAIL]{Style.RESET_ALL}"
WARN  = f"{Fore.YELLOW}[WARN]{Style.RESET_ALL}"
INFO  = f"{Fore.CYAN}[INFO]{Style.RESET_ALL}"
HEAD  = f"{Fore.MAGENTA}"

results = []

def log(status, test_name, detail=""):
    symbol = {"PASS": PASS, "FAIL": FAIL, "WARN": WARN, "INFO": INFO}.get(status, INFO)
    print(f"  {symbol} {test_name}")
    if detail:
        print(f"         {Fore.WHITE}{detail}{Style.RESET_ALL}")
    results.append({"status": status, "test": test_name, "detail": detail})

def section(title):
    print(f"\n{HEAD}{'─'*60}")
    print(f"  {title}")
    print(f"{'─'*60}{Style.RESET_ALL}")

def get_csrf_token(session, url):
    """Extract antiforgery token from a page."""
    r = session.get(url, verify=False, timeout=10)
    match = re.search(r'<input[^>]+name="__RequestVerificationToken"[^>]+value="([^"]+)"', r.text)
    return match.group(1) if match else None


# ─────────────────────────────────────────────
# TEST GROUPS
# ─────────────────────────────────────────────

def test_security_headers(base_url):
    section("1. HTTP SECURITY HEADERS")
    r = requests.get(base_url, verify=False, timeout=10, allow_redirects=True)
    headers = {k.lower(): v for k, v in r.headers.items()}

    checks = [
        ("x-frame-options",              "Clickjacking protection (X-Frame-Options)"),
        ("x-content-type-options",       "MIME sniffing protection (X-Content-Type-Options)"),
        ("x-xss-protection",             "XSS filter header (X-XSS-Protection)"),
        ("referrer-policy",              "Referrer leakage protection (Referrer-Policy)"),
    ]
    for header, label in checks:
        if header in headers:
            log("PASS", label, f"Value: {headers[header]}")
        else:
            log("FAIL", label, f"Header '{header}' is missing")

    # Check server version disclosure
    server = headers.get("server", "")
    xpow   = headers.get("x-powered-by", "")
    if server:
        log("FAIL", "Server version not disclosed", f"Server header present: '{server}'")
    else:
        log("PASS", "Server version not disclosed")
    if xpow:
        log("FAIL", "X-Powered-By not disclosed", f"Header present: '{xpow}'")
    else:
        log("PASS", "X-Powered-By removed")

    # HTTPS redirect
    http_url = base_url.replace("https://", "http://")
    try:
        r2 = requests.get(http_url, verify=False, timeout=5, allow_redirects=False)
        if r2.status_code in (301, 302) and "https" in r2.headers.get("location","").lower():
            log("PASS", "HTTP redirects to HTTPS")
        else:
            log("WARN", "HTTP does not redirect to HTTPS", f"Status: {r2.status_code}")
    except Exception:
        log("INFO", "HTTP redirect check skipped (port not reachable)")


def test_authentication(base_url, valid_emp, valid_ic):
    section("2. AUTHENTICATION & BRUTE FORCE")
    login_url = f"{base_url}/Auth/Login"
    session = requests.Session()

    # Get CSRF token
    token = get_csrf_token(session, login_url)
    if not token:
        log("WARN", "Could not retrieve CSRF token from login page")
        return session

    # 2a. Valid login works
    r = session.post(login_url, verify=False, timeout=10, data={
        "__RequestVerificationToken": token,
        "Username": valid_emp,
        "Password": valid_ic
    }, allow_redirects=True)
    if "/Home/Index" in r.url or "Dashboard" in r.text or "Training" in r.text:
        log("PASS", "Valid credentials authenticate successfully")
    else:
        log("FAIL", "Valid credentials did NOT authenticate — check emp/ic args")

    # Logout
    session.get(f"{base_url}/Auth/Logout", verify=False, timeout=5)

    # 2b. Wrong password rejected
    token = get_csrf_token(session, login_url)
    r = session.post(login_url, verify=False, timeout=10, data={
        "__RequestVerificationToken": token,
        "Username": valid_emp,
        "Password": "WRONGPASSWORD99999"
    })
    if r.status_code == 200 and ("/Home" not in r.url):
        log("PASS", "Wrong password correctly rejected")
    else:
        log("FAIL", "Wrong password was NOT rejected!")

    # 2c. Brute force delay — measure time for 3 failed attempts
    token = get_csrf_token(session, login_url)
    times = []
    for _ in range(3):
        start = time.time()
        session.post(login_url, verify=False, timeout=15, data={
            "__RequestVerificationToken": token or "",
            "Username": valid_emp,
            "Password": f"WRONGPW_{time.time()}"
        })
        token = get_csrf_token(session, login_url)
        times.append(time.time() - start)

    avg = sum(times) / len(times)
    if avg >= 1.0:
        log("PASS", f"Brute force delay active", f"Avg response time on failure: {avg:.2f}s")
    else:
        log("FAIL", f"No brute force delay detected", f"Avg response time: {avg:.2f}s (should be ≥1s)")

    # 2d. Non-existent employee
    token = get_csrf_token(session, login_url)
    r = session.post(login_url, verify=False, timeout=10, data={
        "__RequestVerificationToken": token,
        "Username": "XXXXNOTREAL",
        "Password": "anything"
    })
    if "/Home" not in r.url:
        log("PASS", "Non-existent employee correctly rejected")
    else:
        log("FAIL", "Non-existent employee was authenticated!")

    return session


def test_csrf(base_url, valid_emp, valid_ic):
    section("3. CSRF PROTECTION")
    login_url = f"{base_url}/Auth/Login"

    # Login first
    session = requests.Session()
    token = get_csrf_token(session, login_url)
    session.post(login_url, verify=False, timeout=10, data={
        "__RequestVerificationToken": token,
        "Username": valid_emp,
        "Password": valid_ic
    }, allow_redirects=True)

    # Try admin POST endpoints WITHOUT csrf token
    endpoints = [
        ("ToggleActive",   {"empID": valid_emp}),
        ("DeleteEmployee", {"empID": "FAKEDEL999"}),
        ("SaveEmployee",   {"EmployeeID": "FAKE999", "UserName": "Hacker"}),
    ]
    for action, data in endpoints:
        r = session.post(f"{base_url}/Admin/{action}", verify=False, timeout=10,
                         data=data)  # no __RequestVerificationToken
        if r.status_code in (400, 403, 500) or "AntiForgery" in r.text or "Bad Request" in r.text:
            log("PASS", f"CSRF blocked on /Admin/{action}", f"Status: {r.status_code}")
        elif r.status_code == 302:
            log("PASS", f"CSRF redirected (likely rejected) on /Admin/{action}")
        else:
            try:
                j = r.json()
                if not j.get("success", True):
                    log("PASS", f"CSRF rejected on /Admin/{action}", f"Response: {j.get('message','')}")
                else:
                    log("FAIL", f"CSRF NOT blocked on /Admin/{action}!", f"Response: {r.text[:100]}")
            except Exception:
                log("WARN", f"CSRF check inconclusive on /Admin/{action}", f"Status: {r.status_code}")

    # Login form itself
    r = requests.post(login_url, verify=False, timeout=10, data={
        "Username": valid_emp,
        "Password": valid_ic
        # no token
    })
    if r.status_code in (400, 403, 500) or "AntiForgery" in r.text:
        log("PASS", "CSRF blocked on /Auth/Login")
    else:
        log("WARN", "Login CSRF check inconclusive", f"Status: {r.status_code}")


def test_user_enumeration(base_url, valid_emp):
    section("4. USER ENUMERATION")

    # LookupEmployee with valid ID
    r = requests.get(f"{base_url}/Auth/LookupEmployee",
                     params={"id": valid_emp}, verify=False, timeout=10)
    try:
        j = r.json()
        if j.get("found"):
            fields = list(j.keys())
            if "department" in fields:
                log("FAIL", "LookupEmployee exposes department", f"Fields returned: {fields}")
            else:
                log("PASS", "LookupEmployee does not expose department", f"Fields: {fields}")
            if "name" in fields:
                log("WARN", "LookupEmployee exposes employee name",
                    "Consider removing — allows harvesting names via ID scanning")
            else:
                log("PASS", "LookupEmployee does not expose name")
        else:
            log("WARN", "LookupEmployee returned not-found for valid emp ID — check args")
    except Exception:
        log("WARN", "LookupEmployee returned non-JSON", f"Status: {r.status_code}")

    # Scan a range of IDs — measure if responses differ (timing attack)
    fake_ids = ["XXXXFAKE001", "XXXXFAKE002", "XXXXFAKE003"]
    times_found, times_notfound = [], []
    for fid in fake_ids:
        start = time.time()
        requests.get(f"{base_url}/Auth/LookupEmployee",
                     params={"id": fid}, verify=False, timeout=10)
        times_notfound.append(time.time() - start)

    for _ in range(3):
        start = time.time()
        requests.get(f"{base_url}/Auth/LookupEmployee",
                     params={"id": valid_emp}, verify=False, timeout=10)
        times_found.append(time.time() - start)

    diff = abs(sum(times_found)/3 - sum(times_notfound)/3)
    if diff < 0.3:
        log("PASS", "No significant timing difference between found/not-found", f"Diff: {diff:.3f}s")
    else:
        log("WARN", "Timing difference may reveal valid IDs", f"Diff: {diff:.3f}s")


def test_authorization(base_url, valid_emp, valid_ic):
    section("5. AUTHORIZATION & ACCESS CONTROL")

    login_url = f"{base_url}/Auth/Login"

    # Test unauthenticated access to protected pages
    session = requests.Session()
    protected = [
        "/Home/Index",
        "/Training/Part1",
        "/Training/Part2",
        "/Admin/Dashboard",
    ]
    for path in protected:
        r = session.get(f"{base_url}{path}", verify=False, timeout=10, allow_redirects=True)
        if "/Auth/Login" in r.url or r.status_code in (401, 403):
            log("PASS", f"Unauthenticated access blocked: {path}")
        else:
            log("FAIL", f"Unauthenticated access ALLOWED: {path}", f"Status: {r.status_code}")

    # Test authenticated non-admin cannot access admin endpoints
    token = get_csrf_token(session, login_url)
    session.post(login_url, verify=False, timeout=10, data={
        "__RequestVerificationToken": token,
        "Username": valid_emp,
        "Password": valid_ic
    }, allow_redirects=True)

    admin_pages = ["/Admin/Dashboard", "/Admin/GetScoresJson", "/Admin/GetEmployeesJson"]
    for path in admin_pages:
        r = session.get(f"{base_url}{path}", verify=False, timeout=10, allow_redirects=True)
        # If user is admin, these will pass — warn either way
        if r.status_code in (401, 403) or "/Home" in r.url or "/Auth" in r.url:
            log("PASS", f"Non-admin blocked from: {path}")
        elif r.status_code == 200:
            try:
                j = r.json()
                if "error" in j:
                    log("PASS", f"Admin endpoint returned error for non-admin: {path}")
                else:
                    log("WARN", f"Admin endpoint accessible — verify user is not admin: {path}")
            except Exception:
                log("WARN", f"Admin page returned 200 — user may be admin: {path}")


def test_sql_injection(base_url, valid_emp, valid_ic):
    section("6. SQL INJECTION")

    login_url = f"{base_url}/Auth/Login"
    session = requests.Session()
    token = get_csrf_token(session, login_url)

    # Classic SQL injection payloads in login
    payloads = [
        ("' OR '1'='1",         "Classic OR bypass"),
        ("' OR 1=1 --",         "Comment bypass"),
        ("admin'--",             "Admin comment bypass"),
        ("' UNION SELECT 1--",   "UNION injection"),
        ("'; DROP TABLE empMaster_lists--", "DROP TABLE"),
    ]

    for payload, label in payloads:
        token = get_csrf_token(session, login_url)
        r = session.post(login_url, verify=False, timeout=10, data={
            "__RequestVerificationToken": token or "",
            "Username": payload,
            "Password": payload
        }, allow_redirects=True)
        # Should stay on login page or error — NOT redirect to Home
        if "/Home" in r.url or "Dashboard" in r.text:
            log("FAIL", f"SQL injection may have succeeded: {label}", f"Payload: {payload}")
        else:
            log("PASS", f"SQL injection blocked: {label}")

    # Test LookupEmployee endpoint
    sqli_ids = ["' OR '1'='1", "E001' --", "1; DROP TABLE--"]
    for payload in sqli_ids:
        r = requests.get(f"{base_url}/Auth/LookupEmployee",
                         params={"id": payload}, verify=False, timeout=10)
        if r.status_code == 500:
            log("FAIL", f"SQL error on LookupEmployee — possible injection", f"Payload: {payload}")
        else:
            log("PASS", f"LookupEmployee handled injection payload safely: {payload[:30]}")


def test_xss(base_url):
    section("7. XSS (CROSS-SITE SCRIPTING)")

    login_url = f"{base_url}/Auth/Login"
    session = requests.Session()

    xss_payloads = [
        "<script>alert(1)</script>",
        "<img src=x onerror=alert(1)>",
        "'\"><svg onload=alert(1)>",
        "javascript:alert(1)",
    ]

    token = get_csrf_token(session, login_url)
    for payload in xss_payloads:
        r = session.post(login_url, verify=False, timeout=10, data={
            "__RequestVerificationToken": token or "",
            "Username": payload,
            "Password": "anything"
        })
        # Payload should be HTML-encoded in the response, not raw
        if payload in r.text:
            log("FAIL", f"XSS payload reflected unescaped", f"Payload: {payload[:50]}")
        elif re.search(r"<script>|onerror=|onload=", r.text):
            log("FAIL", f"Possible XSS in response", f"Payload: {payload[:50]}")
        else:
            log("PASS", f"XSS payload correctly escaped/rejected: {payload[:40]}")

    # Check LookupEmployee reflection
    for payload in xss_payloads[:2]:
        r = requests.get(f"{base_url}/Auth/LookupEmployee",
                         params={"id": payload}, verify=False, timeout=10)
        if payload in r.text:
            log("FAIL", "XSS payload reflected in LookupEmployee response", f"Payload: {payload[:50]}")
        else:
            log("PASS", f"LookupEmployee safely handled XSS payload")


def test_session_security(base_url, valid_emp, valid_ic):
    section("8. SESSION SECURITY")

    login_url = f"{base_url}/Auth/Login"
    session = requests.Session()

    # Get pre-login session cookie
    r = session.get(login_url, verify=False, timeout=10)
    pre_session_id = session.cookies.get("ASP.NET_SessionId", "")

    # Login
    token = get_csrf_token(session, login_url)
    session.post(login_url, verify=False, timeout=10, data={
        "__RequestVerificationToken": token,
        "Username": valid_emp,
        "Password": valid_ic
    }, allow_redirects=True)

    post_session_id = session.cookies.get("ASP.NET_SessionId", "")

    if pre_session_id and post_session_id and pre_session_id != post_session_id:
        log("PASS", "Session ID regenerated after login (session fixation protection)")
    elif not pre_session_id:
        log("INFO", "No pre-login session cookie issued — cannot compare")
    else:
        log("WARN", "Session ID NOT regenerated after login",
            "Session fixation risk — consider Session.Clear() before setting values")

    # Check cookie flags
    for cookie in session.cookies:
        if cookie.name == "ASP.NET_SessionId":
            flags = []
            if cookie.has_nonstandard_attr("HttpOnly"):
                flags.append("HttpOnly")
            if cookie.secure:
                flags.append("Secure")
            if "HttpOnly" in flags:
                log("PASS", "Session cookie has HttpOnly flag")
            else:
                log("FAIL", "Session cookie missing HttpOnly flag — JS can read it")
            if "Secure" in flags:
                log("PASS", "Session cookie has Secure flag")
            else:
                log("WARN", "Session cookie missing Secure flag (OK if HTTP-only intranet)")

    # Logout invalidates session
    home_url = f"{base_url}/Home/Index"
    session.get(f"{base_url}/Auth/Logout", verify=False, timeout=5)
    r = session.get(home_url, verify=False, timeout=10, allow_redirects=True)
    if "/Auth/Login" in r.url:
        log("PASS", "Session correctly invalidated after logout")
    else:
        log("FAIL", "Session still valid after logout!", f"Redirected to: {r.url}")


def test_directory_traversal(base_url):
    section("9. PATH TRAVERSAL & SENSITIVE FILE EXPOSURE")

    sensitive_paths = [
        "/Web.config",
        "/web.config",
        "/.git/config",
        "/App_Data/",
        "/bin/ABC_WebApp.dll",
        "/Views/Web.config",
        "/Global.asax",
        "/../Web.config",
        "/Content/../../../../Web.config",
    ]
    for path in sensitive_paths:
        r = requests.get(f"{base_url}{path}", verify=False, timeout=10, allow_redirects=False)
        if r.status_code == 200 and len(r.content) > 100:
            log("FAIL", f"Sensitive file accessible: {path}", f"Status: {r.status_code}, Size: {len(r.content)}b")
        elif r.status_code in (403, 404):
            log("PASS", f"Blocked: {path}", f"Status: {r.status_code}")
        else:
            log("INFO", f"Returned {r.status_code}: {path}")


def test_error_handling(base_url):
    section("10. ERROR HANDLING & INFO DISCLOSURE")

    # Trigger a 404
    r = requests.get(f"{base_url}/ThisPageDoesNotExist12345", verify=False, timeout=10)
    if r.status_code == 404:
        if "Stack Trace" in r.text or "System." in r.text or "at System" in r.text:
            log("FAIL", "404 page exposes stack trace / .NET internals")
        else:
            log("PASS", "404 page does not expose internals")

    # Trigger a 500 with malformed input
    r = requests.get(f"{base_url}/Auth/LookupEmployee", params={"id": "A"*5000},
                     verify=False, timeout=10)
    if r.status_code == 500:
        if "Stack Trace" in r.text or "System." in r.text:
            log("FAIL", "500 error exposes stack trace", "Set <customErrors mode='On'> in Web.config")
        else:
            log("PASS", "500 error handled gracefully without stack trace")
    else:
        log("PASS", f"Oversized input handled safely", f"Status: {r.status_code}")


# ─────────────────────────────────────────────
# SUMMARY REPORT
# ─────────────────────────────────────────────

def print_summary():
    print(f"\n{HEAD}{'═'*60}")
    print(f"  SECURITY TEST SUMMARY")
    print(f"{'═'*60}{Style.RESET_ALL}\n")

    counts = {"PASS": 0, "FAIL": 0, "WARN": 0, "INFO": 0}
    failures = []
    warnings = []

    for r in results:
        counts[r["status"]] = counts.get(r["status"], 0) + 1
        if r["status"] == "FAIL":
            failures.append(r)
        elif r["status"] == "WARN":
            warnings.append(r)

    print(f"  {Fore.GREEN}PASS: {counts['PASS']:3d}{Style.RESET_ALL}   "
          f"{Fore.RED}FAIL: {counts['FAIL']:3d}{Style.RESET_ALL}   "
          f"{Fore.YELLOW}WARN: {counts['WARN']:3d}{Style.RESET_ALL}   "
          f"{Fore.CYAN}INFO: {counts['INFO']:3d}{Style.RESET_ALL}")

    if failures:
        print(f"\n{Fore.RED}  ── FAILURES (fix immediately) ──{Style.RESET_ALL}")
        for f in failures:
            print(f"  {Fore.RED}✗{Style.RESET_ALL} {f['test']}")
            if f["detail"]:
                print(f"    {f['detail']}")

    if warnings:
        print(f"\n{Fore.YELLOW}  ── WARNINGS (review recommended) ──{Style.RESET_ALL}")
        for w in warnings:
            print(f"  {Fore.YELLOW}!{Style.RESET_ALL} {w['test']}")
            if w["detail"]:
                print(f"    {w['detail']}")

    overall = "SECURE" if counts["FAIL"] == 0 else "VULNERABILITIES FOUND"
    color = Fore.GREEN if counts["FAIL"] == 0 else Fore.RED
    print(f"\n  {color}Overall: {overall}{Style.RESET_ALL}\n")


# ─────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="ABC WebApp Security Test Suite — test your OWN app only"
    )
    parser.add_argument("--url", required=True,
                        help="Base URL e.g. https://ioipcnintranet/ABC_NET")
    parser.add_argument("--emp", required=True,
                        help="Valid Employee ID for authenticated tests")
    parser.add_argument("--ic",  required=True,
                        help="IC number (password) for the employee")
    args = parser.parse_args()

    base = args.url.rstrip("/")
    emp  = args.emp
    ic   = args.ic

    print(f"""
{HEAD}╔══════════════════════════════════════════════════╗
║       ABC WebApp Security Test Suite             ║
║       Target: {base:<35}║
╚══════════════════════════════════════════════════╝{Style.RESET_ALL}
{Fore.YELLOW}  ⚠  Run against YOUR OWN application only.{Style.RESET_ALL}
""")

    try:
        test_security_headers(base)
        test_authentication(base, emp, ic)
        test_csrf(base, emp, ic)
        test_user_enumeration(base, emp)
        test_authorization(base, emp, ic)
        test_sql_injection(base, emp, ic)
        test_xss(base)
        test_session_security(base, emp, ic)
        test_directory_traversal(base)
        test_error_handling(base)
    except requests.exceptions.ConnectionError:
        print(f"\n{Fore.RED}  ERROR: Cannot connect to {base}")
        print(f"  Make sure the server is running and reachable.{Style.RESET_ALL}")
        sys.exit(1)
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}  Interrupted by user.{Style.RESET_ALL}")

    print_summary()


if __name__ == "__main__":
    main()