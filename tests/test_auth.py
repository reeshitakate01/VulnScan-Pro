"""Authentication, access control and per-user scoping tests."""
import uuid


def test_home_redirects_anonymous_to_login(anon_client):
    resp = anon_client.get("/")
    assert resp.status_code == 302
    assert "/login" in resp.headers.get("Location", "")


def test_register_logs_in_and_grants_access(anon_client):
    email = f"reg_{uuid.uuid4().hex[:8]}@example.com"
    resp = anon_client.post("/register",
                            data={"email": email, "password": "password123"},
                            follow_redirects=True)
    assert resp.status_code == 200
    # Now authenticated: the scanner home renders.
    assert anon_client.get("/").status_code == 200


def test_register_rejects_short_password(anon_client):
    email = f"short_{uuid.uuid4().hex[:8]}@example.com"
    resp = anon_client.post("/register",
                            data={"email": email, "password": "short"},
                            follow_redirects=True)
    assert b"at least 8" in resp.data.lower() or b"8 characters" in resp.data


def test_login_invalid_credentials(anon_client):
    resp = anon_client.post("/login",
                            data={"email": "nobody@example.com", "password": "wrongpass"},
                            follow_redirects=True)
    assert b"Invalid email or password" in resp.data


def test_logout_then_blocked(client):
    assert client.get("/").status_code == 200
    client.get("/logout")
    # After logout the home page redirects to login again.
    assert client.get("/").status_code == 302


def test_scan_ownership_enforced(app_module, client):
    # Seed a scan owned by a *different* user.
    with app_module.app.app_context():
        from app import db, User, ScanTask
        other = User(email=f"owner_{uuid.uuid4().hex[:8]}@example.com")
        other.set_password("password123")
        db.session.add(other)
        db.session.commit()
        sid = str(uuid.uuid4())
        db.session.add(ScanTask(id=sid, url="http://x", status="completed",
                                score=50, grade="F", user_id=other.id))
        db.session.commit()

    # The logged-in `client` is a different user and must not see it.
    assert client.get(f"/api/scan/{sid}/results").status_code == 404
    assert client.get(f"/results/{sid}").status_code == 404
    assert client.get(f"/api/report/{sid}/json").status_code == 404
