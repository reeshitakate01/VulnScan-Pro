"""Rate limiting is configured on the auth endpoints."""


def test_login_is_rate_limited(app_module):
    limiter = app_module.limiter
    client = app_module.app.test_client()
    limiter.enabled = True
    try:
        # The limit is "10 per minute"; the 11th POST must be throttled.
        statuses = []
        for _ in range(12):
            r = client.post("/login", data={"email": "x@example.com", "password": "nope"})
            statuses.append(r.status_code)
        assert 429 in statuses, f"expected a 429 among {statuses}"
    finally:
        limiter.enabled = False
        # Clear counters so other tests are unaffected.
        try:
            limiter.reset()
        except Exception:
            pass


def test_limiter_disabled_in_tests(app_module):
    assert app_module.limiter.enabled is False
