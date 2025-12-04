from flask import (
    abort,
    render_template,
    request,
    redirect,
    url_for,
    flash,
    session,
    jsonify,
)
from http import HTTPStatus
import requests
from werkzeug.exceptions import InternalServerError
from flask import Blueprint, Response
from flask_login import current_user, login_required, logout_user
import base64

# Removed unused authentication_redirect import
from accounts.email_utils import (
    send_reset_password,
    send_volunteer_thank_you_email,
    send_documents_email,
)
import gzip
from werkzeug.utils import secure_filename
from accounts.forms import (
    RegisterForm,
    LoginForm,
    ForgotPasswordForm,
    ResetPasswordForm,
    ChangePasswordForm,
    EditUserProfileForm,
)
from flask import current_app
import datetime as _dt  # avoid unused direct imports
import re
import os
import shutil

# Removed unused json, urllib.parse, SQLAlchemy, and Migrate imports
from flask_cors import CORS, cross_origin
from accounts.dbqueries import (
    print_all_tables,
    insertUserIntodb,
    authenticate,
    get_user_by_email,
    verify_token,
    get_user_by_id,
    activate_user_and_expire_token,
    get_users,
    reset_password_and_expire_token,
    check_password,
    update_password,
    update_user_details,
    update_user_profile,
    get_profile_by_user_id,
    activate_user,
    send_confirmation,
    verify_user,
    get_users_and_profiles,
    get_users_with_profiles_by_id,
    delete_user_and_profiles,
    insert_copies,
)

"""
This accounts blueprint defines routes and templates related to user management
within our application.
"""
# Import only if used via current_app config; remove direct constants
from dotenv import load_dotenv

load_dotenv()
accounts = Blueprint("accounts", __name__, template_folder="templates")
# Note: Use the app factory to create the Flask app and register this blueprint.
# Avoid creating a separate Flask app instance in a blueprint module.
CORS(current_app) if current_app else None

@accounts.before_request
def allow_analytics_post():
    # Bypass auth/redirects for analytics tracker POSTs
    if request.endpoint == 'accounts.track_event':
        return None


@accounts.before_request
def enforce_inactivity_logout():
    """Auto-logout authenticated users after configured inactivity window.

    Inactivity is measured using the latest `analytics_events.created_at` for the current `session_id`.
    If no activity is found or it's older than `INACTIVITY_LOGOUT_MINUTES`, logout and redirect to login.
    """
    try:
        # Skip for tracker endpoint and static assets to avoid loops
        skip_endpoints = {
            'accounts.track_event',
            'static',
        }
        if request.endpoint in skip_endpoints:
            return None

        # Only enforce for authenticated users
        if not (hasattr(current_user, 'is_authenticated') and current_user.is_authenticated):
            return None

        # Identify session
        sess_id = session.get('session_id') or request.cookies.get('session')
        if not sess_id:
            return None

        # Configured inactivity window
        max_minutes = current_app.config.get('INACTIVITY_LOGOUT_MINUTES', 60)
        if not isinstance(max_minutes, (int, float)) or max_minutes <= 0:
            return None

        # Query latest activity timestamp for this session
        from accounts.dbqueries import get_connection
        conn = get_connection(); cur = conn.cursor()
        cur.execute(
            """
            SELECT MAX(created_at)
            FROM analytics_events
            WHERE session_id = %s
            """,
            (sess_id,)
        )
        row = cur.fetchone()
        cur.close(); conn.close()

        last_ts = row[0] if row else None
        # If no activity recorded, treat as inactive
        inactive = True
        if last_ts is not None:
            # Compare with current time
            from datetime import datetime, timezone, timedelta
            now = datetime.now(timezone.utc)
            # last_ts may be timezone-aware from DB; ensure comparable
            try:
                age = now - last_ts
            except Exception:
                # Fallback: assume inactive
                age = timedelta(minutes=max_minutes + 1)
            inactive = age > timedelta(minutes=float(max_minutes))

        if inactive:
            # Record logout event and clear session
            try:
                from accounts.dbqueries import get_connection as _get_conn
                c2 = _get_conn(); k2 = c2.cursor()
                k2.execute(
                    """
                    INSERT INTO analytics_events (user_id, session_id, event_type, page_path)
                    VALUES (%s, %s, 'logout', %s)
                    """,
                    (
                        getattr(current_user, 'user_id', None),
                        sess_id,
                        request.path,
                    )
                )
                c2.commit(); k2.close(); c2.close()
            except Exception:
                pass

            # Perform logout
            try:
                logout_user()
            except Exception:
                pass
            session.clear()
            resp = redirect(url_for('accounts.login'))
            try:
                resp.delete_cookie('session')
            except Exception:
                pass
            flash('You have been logged out due to inactivity.', 'info')
            return resp
        return None
    except Exception:
        # Fail open to avoid breaking normal flow
        return None


@accounts.route("/analytics/track", methods=["POST"], strict_slashes=False)
@accounts.route("/analytics/track/", methods=["POST"], strict_slashes=False)
@cross_origin()
def track_event():
    data = request.get_json(silent=True) or {}
    event_type = data.get("event_type")
    # Use the actual page URL where the event occurred
    # Prefer client-provided value, then Referer header, then full URL
    referer = request.headers.get("Referer") or request.referrer
    page_path = data.get("page_path") or referer or request.url
    element_id = data.get("element_id")
    area = data.get("area")
    duration_ms = data.get("duration_ms")
    session_id = session.get("session_id") or request.cookies.get("session")
    user_id = (
        getattr(current_user, "user_id", None)
        if hasattr(current_user, "is_authenticated") and current_user.is_authenticated
        else None
    )
    ip = request.headers.get("X-Forwarded-For", request.remote_addr)
    ua = request.headers.get("User-Agent")

    if not event_type or not page_path:
        return jsonify({"ok": False, "error": "missing event_type or page_path"}), 400

    # Temporary safeguard: avoid DB length errors by truncating known long fields
    # The current DB limits appear to be VARCHAR(64) for some columns. We truncate conservatively.
    def _truncate(val, max_len):
        if val is None:
            return None
        try:
            s = str(val)
            return s[:max_len]
        except Exception:
            return val

    # Truncate potentially long values to 64 chars to match existing schema
    page_path = _truncate(page_path, 64)
    user_agent_safe = _truncate(ua, 64)
    element_id = _truncate(element_id, 64)
    area = _truncate(area, 64)
    session_id = _truncate(session_id, 64)
    ip = _truncate(ip, 64)

    # Insert via psycopg
    try:
        from accounts.dbqueries import get_connection

        conn = get_connection()
        cur = conn.cursor()
        cur.execute(
            """
            INSERT INTO analytics_events
            (user_id, session_id, event_type, page_path, element_id, area, duration_ms, ip_address, user_agent)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
            """,
            (
                user_id,
                session_id,
                event_type,
                page_path,
                element_id,
                area,
                duration_ms,
                ip,
                user_agent_safe,
            ),
        )
        conn.commit()
        cur.close()
        conn.close()
        return jsonify({"ok": True})
    except Exception as e:
        # Log the error for visibility; avoid breaking UX
        try:
            print("[analytics.track_event] insert failed:", e)
            cur.close()
            conn.close()
        except Exception:
            pass
        # Return a JSON payload so we can detect failures during debugging
        return jsonify({"ok": False, "error": str(e)}), 200


@accounts.route("/admin/analytics")
def admin_analytics():
    # Guard: allow admins via session or Flask-Login
    from flask import session
    role = None
    try:
        role = (session.get("user") or {}).get("role")
    except Exception:
        role = None
    if not role:
        role = getattr(current_user, "role", None)
    if not role or str(role).lower() != "admin":
        # Not authorized; redirect to login instead of 403
        return redirect(url_for("accounts.login"))

    # Aggregate stats
    from accounts.dbqueries import get_connection

    conn = get_connection()
    cur = conn.cursor()

    stats = {}
    try:
        # Total events
        cur.execute("SELECT COUNT(*) FROM analytics_events")
        stats["total_events"] = cur.fetchone()[0]

        # Page views per page
        cur.execute(
            """
            SELECT page_path, COUNT(*)
            FROM analytics_events
            WHERE event_type = 'page_view'
            GROUP BY page_path
            ORDER BY COUNT(*) DESC
        """
        )
        stats["page_views"] = cur.fetchall()

        # Clicks per page
        cur.execute(
            """
            SELECT page_path, COUNT(*)
            FROM analytics_events
            WHERE event_type = 'click'
            GROUP BY page_path
            ORDER BY COUNT(*) DESC
        """
        )
        stats["clicks_per_page"] = cur.fetchall()

        # Top elements clicked
        cur.execute(
            """
            SELECT element_id, COUNT(*)
            FROM analytics_events
            WHERE event_type = 'click' AND element_id IS NOT NULL
            GROUP BY element_id
            ORDER BY COUNT(*) DESC
            LIMIT 20
        """
        )
        stats["top_elements"] = cur.fetchall()

        # Average session page_view duration
        cur.execute(
            """
            SELECT AVG(duration_ms)
            FROM analytics_events
            WHERE event_type = 'page_view' AND duration_ms IS NOT NULL
        """
        )
        stats["avg_view_duration"] = cur.fetchone()[0]
    finally:
        cur.close()
        conn.close()

    return render_template("admin_analytics.html", stats=stats)


@accounts.route("/admin/analytics/data")
def admin_analytics_data():
    """Provide aggregated analytics data for charts in JSON."""
    # Admin guard
    role = None
    try:
        role = (session.get("user") or {}).get("role")
    except Exception:
        role = None
    if not role:
        role = getattr(current_user, "role", None)
    if not role or str(role).lower() != "admin":
        return jsonify({"error": "unauthorized"}), 401

    from accounts.dbqueries import get_connection

    conn = get_connection()
    cur = conn.cursor()
    payload = {}
    try:
        # Time series: events per day (last 30 days)
        cur.execute(
            """
            SELECT DATE(created_at) AS d, COUNT(*)
            FROM analytics_events
            WHERE created_at >= NOW() - INTERVAL '30 days'
            GROUP BY d
            ORDER BY d
            """
        )
        rows = cur.fetchall()
        payload["events_per_day"] = {str(r[0]): r[1] for r in rows}

        # Events by type (counts)
        cur.execute(
            """
            SELECT event_type, COUNT(*)
            FROM analytics_events
            GROUP BY event_type
            ORDER BY COUNT(*) DESC
            """
        )
        payload["events_by_type"] = [[r[0], r[1]] for r in cur.fetchall()]

        # Page views bar
        cur.execute(
            """
            SELECT page_path, COUNT(*)
            FROM analytics_events
            WHERE event_type = 'page_view'
            GROUP BY page_path
            ORDER BY COUNT(*) DESC
            LIMIT 15
            """
        )
        payload["page_views"] = [[r[0], r[1]] for r in cur.fetchall()]

        # Clicks by element (top 20)
        cur.execute(
            """
            SELECT COALESCE(element_id, 'unknown') AS el, COUNT(*)
            FROM analytics_events
            WHERE event_type = 'click'
            GROUP BY el
            ORDER BY COUNT(*) DESC
            LIMIT 20
            """
        )
        payload["clicks_by_element"] = [[r[0], r[1]] for r in cur.fetchall()]

        # Clicks per page (top 15)
        cur.execute(
            """
            SELECT page_path, COUNT(*)
            FROM analytics_events
            WHERE event_type = 'click'
            GROUP BY page_path
            ORDER BY COUNT(*) DESC
            LIMIT 15
            """
        )
        payload["clicks_per_page"] = [[r[0], r[1]] for r in cur.fetchall()]

        # Browsers breakdown (user agent substring match, simplistic)
        cur.execute(
            """
            SELECT
                CASE
                    WHEN user_agent ILIKE '%Chrome%' THEN 'Chrome'
                    WHEN user_agent ILIKE '%Firefox%' THEN 'Firefox'
                    WHEN user_agent ILIKE '%Safari%' THEN 'Safari'
                    WHEN user_agent ILIKE '%Edge%' THEN 'Edge'
                    ELSE 'Other'
                END AS browser,
                COUNT(*)
            FROM analytics_events
            GROUP BY browser
            ORDER BY COUNT(*) DESC
            """
        )
        payload["browsers"] = [[r[0], r[1]] for r in cur.fetchall()]

        # Devices breakdown (mobile vs desktop, heuristic by UA containing 'Mobi')
        cur.execute(
            """
            SELECT CASE WHEN user_agent ILIKE '%Mobi%' THEN 'Mobile' ELSE 'Desktop' END AS device,
                   COUNT(*)
            FROM analytics_events
            GROUP BY device
            ORDER BY COUNT(*) DESC
            """
        )
        payload["devices"] = [[r[0], r[1]] for r in cur.fetchall()]

        # Average view duration per day (last 30 days)
        cur.execute(
            """
            SELECT DATE(created_at) AS d, AVG(duration_ms)
            FROM analytics_events
            WHERE event_type = 'page_view' AND duration_ms IS NOT NULL
              AND created_at >= NOW() - INTERVAL '30 days'
            GROUP BY d
            ORDER BY d
            """
        )
        payload["avg_duration_per_day"] = {str(r[0]): float(r[1]) for r in cur.fetchall()}

        # Heatmap: counts by weekday (0-6) and hour (0-23)
        cur.execute(
            """
            SELECT EXTRACT(DOW FROM created_at)::int AS dow,
                   EXTRACT(HOUR FROM created_at)::int AS hr,
                   COUNT(*)
            FROM analytics_events
            GROUP BY dow, hr
            ORDER BY dow, hr
            """
        )
        heat = cur.fetchall()
        payload["heatmap"] = [[int(r[0]), int(r[1]), int(r[2])] for r in heat]

        # Users growth: newly created profiles per month (proxy for new users) - last 12 months
        try:
            cur.execute(
                """
                SELECT TO_CHAR(DATE_TRUNC('month', created_at), 'YYYY-MM') AS ym, COUNT(*)
                FROM user_profile
                WHERE created_at >= NOW() - INTERVAL '12 months'
                GROUP BY ym
                ORDER BY ym
                """
            )
            users_rows = cur.fetchall()
            payload["users_per_month"] = {str(r[0]): int(r[1]) for r in users_rows}
        except Exception as e:
            payload["users_per_month_error"] = str(e)

        # Currently logged in users (active sessions): latest event per session not 'logout'
        # Also return their last known IP to enable client-side geolocation
        activity_window_minutes = current_app.config.get('ANALYTICS_ACTIVE_WINDOW_MINUTES', None)
        time_filter = ""
        params = []
        if activity_window_minutes and isinstance(activity_window_minutes, (int, float)) and activity_window_minutes > 0:
            time_filter = " AND created_at >= NOW() - (%s)::interval"
            params.append(f"{int(activity_window_minutes)} minutes")

        query_active = (
            """
            WITH latest AS (
                SELECT ae.session_id, MAX(ae.created_at) AS last_ts
                FROM analytics_events ae
                WHERE ae.session_id IS NOT NULL
            """ + time_filter + """
                GROUP BY ae.session_id
            )
            SELECT ae2.session_id, ae2.ip_address
            FROM latest l
            JOIN analytics_events ae2
              ON ae2.session_id = l.session_id AND ae2.created_at = l.last_ts
            WHERE LOWER(ae2.event_type) <> 'logout'
            """
        )
        if params:
            cur.execute(query_active, params)
        else:
            cur.execute(query_active)
        active_rows = cur.fetchall()
        payload["active_sessions_count"] = len(active_rows)
        payload["active_session_ips"] = [r[1] for r in active_rows if r[1] is not None]

        return jsonify(payload)
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        try:
            cur.close()
            conn.close()
        except Exception:
            pass


@accounts.route("/debug/db")
def debug_db() -> Response:
    try:
        from accounts.dbqueries import get_connection

        conn = get_connection()
        cur = conn.cursor()
        # Show current database name
        cur.execute("SELECT current_database();")
        dbname = cur.fetchone()[0]
        # List tables in public schema
        cur.execute(
            """
            SELECT tablename
            FROM pg_catalog.pg_tables
            WHERE schemaname = 'public'
            ORDER BY tablename;
        """
        )
        tables = [r[0] for r in cur.fetchall()]
        return {"database": dbname, "tables": tables}
    except Exception as e:
        return {"error": str(e)}, 500
    finally:
        try:
            cur.close()
            conn.close()
        except Exception:
            pass


@accounts.route("/debug/analytics")
def debug_analytics() -> Response:
    """Return analytics events relevant to the current user/session for debugging.

    Filters by either authenticated user_id or session_id cookie, ordered by newest first.
    Includes event_type, page_path, element_id, duration_ms, created_at.
    """
    try:
        from accounts.dbqueries import get_connection

        # Identify user/session context
        user_id = (
            getattr(current_user, "user_id", None)
            if hasattr(current_user, "is_authenticated") and current_user.is_authenticated
            else None
        )
        session_id = session.get("session_id") or request.cookies.get("session")

        conn = get_connection()
        cur = conn.cursor()

        if user_id:
            cur.execute(
                """
                SELECT user_id, session_id, event_type, page_path, element_id, area, duration_ms, ip_address, user_agent, created_at
                FROM analytics_events
                WHERE user_id = %s
                ORDER BY created_at DESC
                LIMIT 200
                """,
                (user_id,),
            )
        elif session_id:
            cur.execute(
                """
                SELECT user_id, session_id, event_type, page_path, element_id, area, duration_ms, ip_address, user_agent, created_at
                FROM analytics_events
                WHERE session_id = %s
                ORDER BY created_at DESC
                LIMIT 200
                """,
                (session_id,),
            )
        else:
            cur.execute(
                """
                SELECT user_id, session_id, event_type, page_path, element_id, area, duration_ms, ip_address, user_agent, created_at
                FROM analytics_events
                ORDER BY created_at DESC
                LIMIT 100
                """
            )

        rows = cur.fetchall()
        cols = [d[0] for d in cur.description]
        data = [dict(zip(cols, r)) for r in rows]
        return jsonify({"count": len(data), "events": data})
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        try:
            cur.close()
            conn.close()
        except Exception:
            pass


@accounts.route("/register", methods=["GET", "POST"])
def register() -> Response:
    """
    Handling user registration.
    If the user is already authenticated, they are redirected to the index page.

    This view handles both GET and POST requests:
    - GET: Renders the registration form and template.
    - POST: Processes the registration form, creates a new user, and sends a confirmation email.

    :return: Renders the registration template on GET request
    or redirects to login after successful registration.
    """
    form = RegisterForm()

    if form.validate_on_submit():

        first_name = form.data.get("first_name")
        last_name = form.data.get("last_name")
        email = form.data.get("email")
        date_of_birth = form.data.get("date_of_birth")
        gender = form.data.get("gender")
        occupation = form.data.get("occupation")
        contact_number = form.data.get("contact_number")
        address = form.data.get("address")
        postal_code = form.data.get("postal_code")
        # Use WTForms field access to avoid mismatches
        role = form.role.data
        password = form.data.get("password")

        id_copy_filename = None
        certificates_filename = None
        if form.id_copy.data:
            id_copy_filename = secure_filename(form.id_copy.data)
            id_copy_destination = os.path.join(
                current_app.config["UPLOAD_FOLDER_SUPPORTING_DOCUMENTS"],
                id_copy_filename,
            )
            os.makedirs(os.path.dirname(id_copy_destination), exist_ok=True)
            # form.id_copy.data.save(id_copy_destination)
        if form.certificates.data:
            certificates_filename = secure_filename(form.certificates.data)
            certificates_destination = os.path.join(
                current_app.config["UPLOAD_FOLDER_SUPPORTING_DOCUMENTS"],
                certificates_filename,
            )
            os.makedirs(os.path.dirname(certificates_destination), exist_ok=True)
            # form.certificates.data.save(certificates_destination)

        # Prevent duplicate email
        existing = get_user_by_email(email)
        if existing:
            flash(
                "Email address already registered. Please use a different email.",
                "error",
            )
            return redirect(url_for("accounts.register"))

        # Create user account
        print("[register] Attempting insert for email:", email)
        user = insertUserIntodb(
            first_name,
            last_name,
            email,
            contact_number,
            occupation,
            gender,
            date_of_birth,
            address,
            postal_code,
            role,
            password,
        )

        if not user:
            print("[register] Insert returned None for email:", email)
            # If insert failed, check if email now exists to distinguish duplicate case
            try:
                existing_after = get_user_by_email(email)
                print("[register] Existing after insert check:", bool(existing_after))
            except Exception as e:
                print("[register] Error checking email after failed insert:", e)
                existing_after = {}
            if existing_after:
                flash(
                    "Email address already registered. Please use a different email.",
                    "error",
                )
            else:
                flash(
                    "Registration failed. Please check your inputs and try again.",
                    "error",
                )
            return redirect(url_for("accounts.register"))

        if role == "tutor":
            # Record supporting documents if provided
            insert_copies(id_copy_destination, certificates_filename, user["user_id"])
            send_volunteer_thank_you_email(user)
            send_documents_email(user, id_copy_filename, certificates_filename)
            flash(
                "Thank you for registering with us, a message with more information has been sent to your email.",
                "info",
            )
            return redirect(url_for("accounts.login"))
        else:
            # Non-tutor registration success
            try:
                send_confirmation(user)
            except Exception as e:
                print(f"Error sending confirmation email: {e}")
            flash("Registration successful. Please log in.", "success")
            return redirect(url_for("accounts.login"))

       
    # If POST failed validation, surface concise error messages to help fix inputs
    from flask import request

    if request.method == "POST" and not form.validate():
        for field, errs in form.errors.items():
            for err in errs:
                flash(f"{field}: {err}", "error")
    return render_template("create_account.html", form=form)


@accounts.route("/login", methods=["GET", "POST"])
def login() -> Response:
    """
    Handling user login functionality.
    If the user is already authenticated, they are redirected to the index page.

    This view handles both GET and POST requests:
    - GET: Renders the login form and template.
    - POST: Validates the form and authenticates the user.

    :return: Renders the login template on GET request or redirects based on the login status.
    """
    form = LoginForm()  # A form class for Login Account.

    if form.validate_on_submit():

        email = form.data.get("email", None)
        password = form.data.get("password", None)
        # remember flag not used server-side; omit to avoid unused variable

        # Attempt to authenticate the user from the database.
        user = authenticate(email=email, password=password)

        if not user:
            flash("Invalid email or password. Please try again.", "error")
        else:
            if not user["active"]:
                # User account is not active, send confirmation email.
                send_confirmation(user)

                flash(
                    "Your account is not activate. We sent a confirmation link to your email",
                    "error",
                )
                return redirect(url_for("accounts.login"))

            session["email"] = email

            user = get_user_by_email(email)  # User.get_user_by_email(email=email)
            # Normalize role casing for UI checks
            if isinstance(user, dict) and user.get("role"):
                try:
                    user["role"] = str(user["role"]).lower()
                except Exception:
                    pass
            session["user"] = user
            # Debug: print role and session details to terminal
            try:
                print(f"[login] session.user keys: {list(user.keys())}")
            except Exception as _e:
                print(f"[login] debug print failed: {_e}")
            # Track login event for active user metrics
            try:
                from accounts.dbqueries import get_connection
                conn = get_connection(); cur = conn.cursor()
                cur.execute(
                    """
                    INSERT INTO analytics_events (user_id, session_id, event_type, page_path)
                    VALUES (%s, %s, %s, %s)
                    """,
                    (user.get('user_id'), session.get('session_id'), 'login', '/login')
                )
                conn.commit(); cur.close(); conn.close()
            except Exception:
                try:
                    cur.close(); conn.close()
                except Exception:
                    pass
            flash("You are logged in successfully.", "success")
            return redirect(url_for("accounts.index"))

        return redirect(url_for("accounts.login"))

    return render_template("login.html", form=form)


@accounts.route("/confirm/<token>", methods=["GET", "POST"])
def confirm_account(token=None) -> Response:
    """
    Handling account confirmation request via a token.
    If the token is valid and not expired, the user is activated.

    This view handles both GET and POST requests:
    - GET: Renders the account confirmation template.
    - POST: Activates the user account if the token is valid,
            logs the user in, and redirects to the index page.

    :return: Renders the confirmation template on GET request,
    redirects to login or index after POST.
    """
    # Token comes from URL parameter now

    # Verify the provided token and return token instance.
    auth_token = verify_token(token, current_app.config["ACCOUNT_CONFIRM_SALT"])

    if auth_token:
        # Retrieve the user instance associated with the token by providing user ID.
        user = get_user_by_id(auth_token["user_id"], raise_exception=True)

        if request.method == "POST":
            try:
                # Activate the user's account and expire the token.
                # user['active'] = True
                # auth_token['expire'] = True
                activate_user_and_expire_token(user["user_id"], token)
                # Commit changes to the database.
                # db.session.commit()
            except Exception as e:
                # Handle database error that occur during the account activation.
                raise InternalServerError

            flash(
                f"Welcome {user['first_name']+ ' ' + user['last_name']}, You're registered successfully.",
                "success",
            )
            return redirect(url_for("accounts.index"))

        return render_template("confirm_account.html", token=token)

    # If the token is invalid, return a 404 error
    return abort(HTTPStatus.NOT_FOUND)


@accounts.route("/send_user_data", methods=["POST"])
def send_user_data():

    # Get user data from the incoming request
    user_data = get_users()

    if not user_data:
        return {"error": "No data provided"}
    # Example of the data structure expected by the other app
    target_url = "http://127.0.0.1:7000/receive_user_data"

    try:
        # Send user data to another app (target app) via POST request
        response = requests.post(target_url, json=user_data)

        # Check if the request was successful
        if response.status_code == 200:
            return (
                jsonify(
                    {
                        "message": "Data sent successfully",
                        "status": response.status_code,
                    }
                ),
                200,
            )
        else:
            return (
                jsonify(
                    {
                        "error": "Failed to send data to the target app",
                        "status": response.status_code,
                    }
                ),
                500,
            )

    except requests.exceptions.RequestException as e:
        return jsonify({"error": str(e)}), 500


@accounts.route("/logout")
def logout() -> Response:
    # Capture user/session before clearing
    session_user = session.get("user")
    session_id_val = session.get("session_id")
    # Clear server-side session
    session.clear()
    """
    Logs out the currently authenticated user
    and redirect them to the login page.

    :return: A redirect response to the login page with a success flash message.
    """
    # Log out the user and clear the session.
    logout_user()
    # Track logout event
    try:
        from accounts.dbqueries import get_connection
        conn = get_connection(); cur = conn.cursor()
        cur.execute(
            """
            INSERT INTO analytics_events (user_id, session_id, event_type, page_path)
            VALUES (%s, %s, %s, %s)
            """,
            ((session_user or {}).get('user_id'), session_id_val, 'logout', '/logout')
        )
        conn.commit(); cur.close(); conn.close()
    except Exception:
        try:
            cur.close(); conn.close()
        except Exception:
            pass

  
    flash("You're logout successfully.", "success")
    # Remove client-side session cookie to prevent stale active user count
    resp = redirect(url_for("accounts.index"))
    try:
        resp.delete_cookie("session")
    except Exception:
        pass
    return resp


@accounts.route("/metrics/active_users")
def metrics_active_users(): 
    """Count currently active users based on analytics session activity.

    Definition: sessions whose latest event is not 'logout'. Optional time window
    via `ANALYTICS_ACTIVE_WINDOW_MINUTES` config to restrict to recent activity.
    """
    # Admins and public can see count; keep lightweight
    try:
        # If user is fully logged out (no auth and no session cookie), report 0 locally
        no_auth = not (hasattr(current_user, "is_authenticated") and current_user.is_authenticated)
        no_session_cookie = not bool(request.cookies.get("session"))
        # Only short-circuit to 0 for unauthenticated public viewers without a session cookie.
        # Admins or authenticated users should always see the computed count.
        if no_auth and no_session_cookie:
            return jsonify({"active_users": 0})

        from accounts.dbqueries import get_connection
        conn = get_connection(); cur = conn.cursor()

        # Optional activity window
        activity_window_minutes = current_app.config.get('ANALYTICS_ACTIVE_WINDOW_MINUTES', None)
        time_filter = ""
        params = []
        if activity_window_minutes and isinstance(activity_window_minutes, (int, float)) and activity_window_minutes > 0:
            time_filter = " AND created_at >= NOW() - INTERVAL %s"
            # Build interval literal like '30 minutes'
            params.append(f"{int(activity_window_minutes)} minutes")

        # Prefer session-based latest event; also consider user_id in case cookie/session_id is missing
        query = (
            """
            WITH latest AS (
                SELECT ae.session_id, MAX(ae.created_at) AS last_ts
                FROM analytics_events ae
                WHERE ae.session_id IS NOT NULL
            """ + time_filter + """
                GROUP BY ae.session_id
            )
            SELECT COUNT(*)
            FROM latest l
            JOIN analytics_events ae2
              ON ae2.session_id = l.session_id AND ae2.created_at = l.last_ts
            WHERE LOWER(ae2.event_type) <> 'logout'
            """
        )

        if params:
            cur.execute(query, params)
        else:
            cur.execute(query)

        count = cur.fetchone()[0]
        # If count is 0 and we have an authenticated admin, fallback to user_id latest-event logic
        if (count == 0) and (hasattr(current_user, 'is_authenticated') and current_user.is_authenticated):
            # Count distinct users whose latest event is not logout
            q2 = (
                """
                WITH latest_u AS (
                    SELECT ae.user_id, MAX(ae.created_at) AS last_ts
                    FROM analytics_events ae
                    WHERE ae.user_id IS NOT NULL
                """ + time_filter + """
                    GROUP BY ae.user_id
                )
                SELECT COUNT(*)
                FROM latest_u lu
                JOIN analytics_events ae3
                  ON ae3.user_id = lu.user_id AND ae3.created_at = lu.last_ts
                WHERE LOWER(ae3.event_type) <> 'logout'
                """
            )
            if params:
                cur.execute(q2, params)
            else:
                cur.execute(q2)
            count = cur.fetchone()[0]
        cur.close(); conn.close()
        return jsonify({"active_users": int(count)})
    except Exception as e:
        try:
            cur.close(); conn.close()
        except Exception:
            pass
        return jsonify({"active_users": 0, "error": str(e)}), 500


@accounts.route("/login-in")
def login_in() -> Response:
    """
    Logs out the currently authenticated user
    and redirect them to the login page.

    :return: A redirect response to the login page with a success flash message.
    """
    form = LoginForm()

    flash("You're logout successfully.", "success")
    return render_template("login.html", form=form)


@accounts.route("/forgot/password", methods=["GET", "POST"])
def forgot_password() -> Response:
    """
    Handling forgot password requests by validating the provided email
    and sending a password reset link if the email is registered.

    This view handles both GET and POST requests:
    - GET: Renders the forgot password form and template.
    - POST: Validates the email and sends a reset link if the email exists in the system.

    :return: Renders the forgot password form on GET,
    redirects to login on success, or reloads the form on failure.
    """
    form = ForgotPasswordForm()

    if form.validate_on_submit():
        email = form.data.get("email")

        # Attempt to find the user by email from the database.
        user = get_user_by_email(email=email)

        if user:
            # Send a reset password link to the user's email.
            send_reset_password(user)

            flash("A reset password link sent to your email. Please check.", "success")
            return redirect(url_for("accounts.login"))

        flash("Email address is not registered with us.", "error")
        return redirect(url_for("accounts.forgot_password"))

    return render_template("forgot_password.html", form=form)


@accounts.route("/password/reset", methods=["GET", "POST"])
def reset_password() -> Response:
    """
    Handling password reset requests.

    This function allows users to reset their password by validating a token
    and ensuring the new password meets security criteria.

    This view handles both GET and POST requests:
    - GET: Renders the reset password form and template, if the token is valid.
    - POST: Validates the form, checks password strength, and updates the user's password.

    :return: Renders the reset password form on GET,
    redirects to login on success, or reloads the form on failure.
    """
    token = request.args.get("token", None)
    current_app.config["RESET_PASSWORD_SALT"] = os.getenv(
        "RESET_PASSWORD_SALT", "reset_password_salt"
    )
    # Verify the provided token and return token instance.
    auth_token = verify_token(
        token=token, salt=current_app.config["RESET_PASSWORD_SALT"]
    )

    if auth_token:
        form = ResetPasswordForm()  # A form class to Reset User's Password.

        if form.validate_on_submit():
            password = form.data.get("password")
            confirm_password = form.data.get("confirm_password")

            # Regex pattern to validate password strength.
            re_pattern = r"(?=^.{8,}$)(?=.*\d)(?=.*[!@#$%^&*]+)(?![.\n])(?=.*[A-Z])(?=.*[a-z]).*$"

            if not (password == confirm_password):
                flash("Your new password field's not match.", "error")
            elif not re.match(re_pattern, password):
                flash(
                    "Please choose strong password. It contains at least one alphabet, number, and one special character.",
                    "warning",
                )
            else:
                try:
                    # Retrieve the user by the ID from the token and update their password.
                    user = get_user_by_id(auth_token["user_id"], raise_exception=True)
                    reset_password_and_expire_token(
                        user["user_id"], password, auth_token["token"]
                    )

                except Exception as e:
                    # Handle database error by raising an internal server error.
                    raise InternalServerError

                flash("Your password is changed successfully. Please login.", "success")
                return redirect(url_for("accounts.login"))

            return redirect(url_for("accounts.reset_password", token=token))

        return render_template("reset_password.html", form=form, token=token)

    # If the token is invalid, abort with a 404 Not Found status.
    return abort(HTTPStatus.NOT_FOUND)


@accounts.route("/change/password", methods=["GET", "POST"])
def change_password() -> Response:
    """
    Handling user password change requests.

    This function allows authenticated users to change their password by
    verifying the old password and ensuring the new password meets security criteria.

    This view handles both GET and POST requests:
    - GET: Renders the change password form and template.
    - POST: Validates the form, checks old password correctness, ensures the new
      password meets security standards, and updates the user's password.

    :return: Renders the change password form on GET,
    redirects to index on success, or reloads the form on failure.
    """
    form = ChangePasswordForm()  # A form class to Change User's Password.

    if form.validate_on_submit():
        old_password = form.data.get("old_password")
        new_password = form.data.get("new_password")
        confirm_password = form.data.get("confirm_password")

        # Retrieve the fresh user instance from the database.
        user = get_user_by_id(current_user["user_id"], raise_exception=True)

        # Regex pattern to validate password strength.
        re_pattern = (
            r"(?=^.{8,}$)(?=.*\d)(?=.*[!@#$%^&*]+)(?![.\n])(?=.*[A-Z])(?=.*[a-z]).*$"
        )

        if not check_password(old_password):
            flash("Your old password is incorrect.", "error")
        elif not (new_password == confirm_password):
            flash("Your new password field's not match.", "error")
        elif not re.match(re_pattern, new_password):
            flash(
                "Please choose strong password. It contains at least one alphabet, number, and one special character.",
                "warning",
            )
        else:
            try:
                # Update the user's password.
                # user.set_password(new_password)
                update_password(user["user_id"], new_password)
                # Commit changes to the database.
                # db.session.commit()
            except Exception as e:
                # Handle database error by raising an internal server error.
                raise InternalServerError

            flash("Your password changed successfully.", "success")
            return redirect(url_for("accounts.index"))

        return redirect(url_for("accounts.change_password"))

    return render_template("change_password.html", form=form)


@accounts.route("/")
@accounts.route("/home")
def index() -> Response:
    user = session.get("user")
    print_all_tables()
    """
    Render the homepage for authenticated users.

    :return: Renders the `index.html` template.
    """
    return render_template("index.html", user=user)


@accounts.route("/profile", methods=["GET", "POST"])
def profile() -> Response:
    user_profile = session.get("user")

    if not user_profile:
        return redirect(url_for("accounts.login"))
    form = EditUserProfileForm(obj=user_profile)

    # Retrieve the fresh user+profile based on their ID
    user_full = get_users_with_profiles_by_id(user_profile["user_id"]) or {}

    if form.validate_on_submit():
        # Retrieve form data
        id = user_full[0]["user_id"]
        first_name = form.first_name.data
        last_name = form.last_name.data
        occupation = form.occupation.data
        contact_number = form.contact_number.data
        address = form.address.data
        postal_code = form.postal_code.data
        profile_image = form.profile_image.data
        bio = form.about.data

        # Update the user's main details
        # user.first_name = first_name
        # user.last_name = last_name
        # user.occupation = occupation
        # user.contact_number = contact_number
        # user.address = address
        # user.postal_code = postal_code
        # profile.bio = bio
        update_user_details(
            id, first_name, last_name, occupation, contact_number, address, postal_code
        )

        # Handle profile image upload if provided: save to static/assets/profile
        if profile_image and getattr(profile_image, "filename"):
            filename = secure_filename(profile_image.filename)
            upload_dir = os.path.join(current_app.root_path, "accounts", "static", "assets", "profile")
            os.makedirs(upload_dir, exist_ok=True)
            save_path = os.path.join(upload_dir, filename)
            profile_image.save(save_path)
            update_user_profile(id, bio, filename)

        flash("Your profile was updated successfully.", "success")
        return redirect(url_for("accounts.profile"))

    # Merge session user and full profile for template convenience
    context_user = {**user_full, **(user_profile or {})}
    return render_template("profile.html", form=form, user=context_user)


base64_string = ""


@accounts.route("/innovation")
def innovation():
    user = session.get("user")
    if user:
        id = user["user_id"]
        if not id:
            return redirect(url_for("accounts.login"))
        # Redirect to another application running on a different server or port
        # user = get_user_by_id(id)
        # profile=get_profile_by_user_id(user['id'])
        # user['bio']=profile['bio']

        return redirect(f"https://innovation-ee65.onrender.com?user={id}")
    else:
        return redirect(url_for("accounts.index"))


@accounts.route("/stem_app")
def stem_app():
    user = session.get("user")
    if user:
        id = user["user_id"]
        if not id:
            return redirect(url_for("accounts.login"))
        profile = get_profile_by_user_id(id)
        if profile:
            user["bio"] = profile["bio"]
        return redirect(f"http://127.0.0.1:7000?user={id}")
    else:
        return redirect(url_for("accounts.index"))


@accounts.route("/inventory")
def inventory():
    user = session.get("user")
    if user:
        id = user["user_id"]
        if not id:
            return redirect(url_for("accounts.login"))
        # Redirect to another application running on a different server or port
        return redirect(f"https://inventory-ba3p.onrender.com?user={id}")
    else:
        return redirect(url_for("accounts.index"))


@accounts.route("/stem-app-route/<path:id>", methods=["GET", "POST"])
@cross_origin()  # Enable CORS for this route
def stemapproute(id):
    # Decode URL-encoded characters if present
    import urllib.parse

    decoded_id = urllib.parse.unquote(id)

    if not decoded_id:
        return jsonify({"error": "User not authenticated"}), 401

    # Retrieve user data using the scrypt hash as user_id
    try:
        user = get_user_by_id(decoded_id)
        if not user:
            return jsonify({"error": "User not found"}), 404
    except Exception as e:
        return jsonify({"error": f"Database error: {str(e)}"}), 500

    # Optionally enrich with profile
    profile = get_profile_by_user_id(user["user_id"])
    if profile:
        user["bio"] = profile.get("bio", "")
        avatar = profile.get("avator", "")
        user["avatar"] = convert_image_to_base64_in_folder(avatar) if avatar else None

    return jsonify(user), 200


@accounts.route("/stem_approute/<string:id>", methods=["GET", "POST"])
@cross_origin()  # Enable CORS for this route
def stem_approute(id):
    # Retrieve the logged-in user's email from the session

    if not id:
        return (
            jsonify({"error": "User not authenticated"}),
            401,
        )  # Return a 401 status for unauthenticated requests

    # Retrieve user data by email
    user = get_user_by_id(id)
    if not user:
        return jsonify({"error": "User not found"}), 404

    return jsonify(user), 200


@accounts.route("/stemprofiles", methods=["GET"])
@cross_origin()  # Enable CORS for this route
def stemprofiles():
    # Return all users; do not rely on undefined 'id'
    users = get_users()
    if not users:
        return jsonify({"error": "No users found"}), 404
    return jsonify(users), 200


@accounts.route("/users_profiles", methods=["GET"])
@cross_origin()  # Enable CORS for this route
def users_profiles():
    # Return joined users and profiles
    profiles = get_users_and_profiles()
    if not profiles:
        return jsonify({"error": "No user profiles found"}), 404
    return jsonify(profiles), 200


@accounts.route("/stemuserprofiles/<string:id>", methods=["GET", "POST"])
@cross_origin()  # Enable CORS for this route
def stemuserprofiles(id):

    user = get_user_by_id(id)
    if not user:
        return jsonify({"error": "User not found"}), 404

    profile = get_profile_by_user_id(user["user_id"])
    if profile:
        user["bio"] = profile["bio"]
        user["avatar"] = convert_image_to_base64_in_folder(profile["avator"])
    
    # Return the user data as JSON
    return jsonify(user), 200


@accounts.route(
    "/role/<string:id_copy>/<string:certificate>/<string:user_id>",
    methods=["GET", "POST"],
)
@cross_origin()  # Enable CORS for this route
def role(id_copy, certificate, user_id):

    user = insert_copies(id_copy, certificate, user_id)

    # Return the user data as JSON
    return jsonify(user), 200


@accounts.route("/deleteuserprofiles/<string:id>", methods=["GET", "POST"])
@cross_origin()  # Enable CORS for this route
def deleteuserprofiles(id):

    user = delete_user_and_profiles(id)
    if user:
        return jsonify({"error": "User not deleted"}), 404

    # Return the user data as JSON
    return jsonify(user), 200


@accounts.route(
    "/stemuserprofiles_status/<string:id>/<string:action>", methods=["GET", "POST"]
)
@cross_origin()  # Enable CORS for this route
def stemuserprofiles_status(id, action):
    if action == "verify":
        user = verify_user(id)
    else:
        delete_user_and_profiles(id)

    # Return the user data as JSON
    return jsonify(user), 200


def compress_base64_string(base64_string: str) -> str:
    """
    Compress a Base64-encoded string.

    Args:
        b64_string (str): The Base64 string to compress.

    Returns:
        str: The compressed Base64 string.
    """
    try:

        binary_data = base64.b64decode(base64_string)
        # Compress the binary data
        compressed_data = gzip.compress(binary_data)
        # Encode the compressed data back into a Base64 string
        compressed_b64_string = base64.b64encode(compressed_data)
        compressed_b64_string = base64.b64encode(compressed_b64_string).decode("utf-8")
        return compressed_b64_string
    except Exception as e:
        raise ValueError(f"Error compressing Base64 string: {e}")


def create_folder(folder_name):
    # Create a new folder
    if not os.path.exists(folder_name):
        os.makedirs(folder_name)
        print(f"Folder '{folder_name}' created.")
    return folder_name


def save_filename_in_folder(filename, folder_name):
    # Save the filename in the created folder
    file_path = os.path.join(folder_name, filename)
    with open(file_path, "w") as file:
        file.write(filename)
    return file_path


def convert_image_to_base64_in_folder(image_filename):
    # Read and convert image to Base64 while it's in the folder

    try:
        config = {"base_dir": "accounts\\static\\assets\\"}
        # Get base directory from config
        base_dir = config["base_dir"]

        # Construct path for the uploads folder
        uploads_dir = os.path.join(base_dir, "profile")
        # Ensure absolute path for consistency and security
        image_path = os.path.join(uploads_dir, image_filename)

        # Validate file existence and extension
        if not os.path.exists(image_path):
            print(f"Error: File '{image_filename}' does not exist.")
            return None

        # Check for supported image formats (add more as needed)
        if not image_path.lower().endswith((".jpg", ".jpeg", ".png")):
            print(
                f"Error: Unsupported image format. Supported formats: JPG, JPEG, PNG."
            )
            return None

        with open(image_path, "rb") as image_file:
            encoded_string = base64.b64encode(image_file.read()).decode("utf-8")

        return encoded_string

    except FileNotFoundError:
        print(f"Error: File '{image_filename}' not found.")
    except Exception as e:
        print(f"An error occurred: {str(e)}")

    return None  # Return None on error


def delete_folder(folder_name):
    # Delete the folder and all its contents
    if os.path.exists(folder_name):
        shutil.rmtree(folder_name)
        print(f"Folder '{folder_name}' and its contents deleted.")


def process_image(filename):
    folder_name = "temp_folder"

    # 1. Create a folder
    create_folder(folder_name)

    # 2. Save the image filename in the folder
    image_path = save_filename_in_folder(filename, folder_name)

    # 3. Convert the image to Base64 while it's in the folder
    base64_string = convert_image_to_base64_in_folder(image_path)

    # 4. Delete the folder after conversion
    delete_folder(folder_name)

    # 5. Return the Base64-encoded string
    return base64_string


# Removed stray app-level route; session data should be handled within blueprint or app factory context.


# get_non_superuser_users
