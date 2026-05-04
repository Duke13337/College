from __future__ import annotations

import csv
import hmac
import io
import json
import os
import re
import secrets
from datetime import date, datetime, timedelta
from typing import Optional

from markupsafe import Markup, escape
from urllib.parse import parse_qsl, urlencode

from fastapi import FastAPI, Request, Form, Depends, HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from sqlalchemy import case, or_, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, joinedload
from starlette.middleware.sessions import SessionMiddleware

import auth_utils
import models
from database import engine, SessionLocal

models.Base.metadata.create_all(bind=engine)

_ALTER_SAFE = [
    "ALTER TABLE rooms ADD COLUMN is_under_maintenance BOOLEAN DEFAULT 0",
    "ALTER TABLE colleges ADD COLUMN floor_plan_key VARCHAR(32) DEFAULT 'polytech'",
    "ALTER TABLE rooms ADD COLUMN room_status VARCHAR(24) DEFAULT 'available'",
    "ALTER TABLE rooms ADD COLUMN zone_w INTEGER DEFAULT 14",
    "ALTER TABLE rooms ADD COLUMN zone_h INTEGER DEFAULT 20",
    "ALTER TABLE bookings ADD COLUMN reviewed_at DATETIME",
    "ALTER TABLE bookings ADD COLUMN reviewed_by_id INTEGER",
]

with engine.begin() as conn:
    for stmt in _ALTER_SAFE:
        try:
            conn.execute(text(stmt))
        except Exception:
            pass
    conn.execute(text("UPDATE rooms SET room_status = 'maintenance' WHERE is_under_maintenance = 1"))
    conn.execute(text("UPDATE rooms SET is_under_maintenance = 1 WHERE room_status = 'maintenance'"))
    conn.execute(text("UPDATE rooms SET is_under_maintenance = 0 WHERE room_status IS NOT NULL AND room_status != 'maintenance'"))
    conn.execute(text("UPDATE rooms SET zone_w = 14 WHERE zone_w IS NULL"))
    conn.execute(text("UPDATE rooms SET zone_h = 20 WHERE zone_h IS NULL"))
    conn.execute(text("UPDATE colleges SET floor_plan_key = 'polytech' WHERE floor_plan_key IS NULL OR floor_plan_key = ''"))
    conn.execute(
        text(
            "UPDATE colleges SET floor_plan_key = 'cit' WHERE name LIKE '%Информационных%' OR name LIKE '%информационных%'"
        )
    )

SESSION_SECRET = os.getenv("SESSION_SECRET", "super_secret_key")

app = FastAPI()
app.add_middleware(SessionMiddleware, secret_key=SESSION_SECRET)

STAFF_ROLES = frozenset({"teacher", "admin", "tech_staff"})
BOOKING_ROLES = frozenset({"teacher", "admin"})
MAINTENANCE_ROLES = frozenset({"tech_staff", "admin"})

current_dir = os.path.dirname(os.path.realpath(__file__))
app.mount("/static", StaticFiles(directory=os.path.join(current_dir, "static")), name="static")
templates = Jinja2Templates(directory=os.path.join(current_dir, "templates"))

_CSRF_SESSION_KEY = "_csrf"
_BOOKINGS_FILTER_KEYS = frozenset({"status", "college_id", "date_from", "date_to", "q"})
_BOOKINGS_RETURN_KEYS = _BOOKINGS_FILTER_KEYS | frozenset({"page"})
BOOKINGS_PER_PAGE = 20


def ensure_csrf_token(request: Request) -> str:
    tok = request.session.get(_CSRF_SESSION_KEY)
    if not tok:
        tok = secrets.token_urlsafe(32)
        request.session[_CSRF_SESSION_KEY] = tok
    return tok


def validate_csrf_token(request: Request, submitted: Optional[str]) -> bool:
    expected = request.session.get(_CSRF_SESSION_KEY)
    if not expected or not submitted:
        return False
    return hmac.compare_digest(str(expected), str(submitted))


def csrf_field(request: Request) -> Markup:
    tok = ensure_csrf_token(request)
    return Markup(f'<input type="hidden" name="csrf_token" value="{escape(tok)}">')


templates.env.globals["csrf_field"] = csrf_field


def sanitize_bookings_return_qs(raw: str) -> str:
    pairs = []
    for k, v in parse_qsl((raw or "").strip(), keep_blank_values=False):
        if k not in _BOOKINGS_RETURN_KEYS or not v:
            continue
        if k == "page":
            try:
                if int(v) < 2:
                    continue
            except ValueError:
                continue
        pairs.append((k, v))
    return urlencode(pairs)


def bookings_redirect_url(
    return_qs_form: str,
    *,
    notice: Optional[str] = None,
    error: Optional[str] = None,
) -> str:
    pairs = [(k, v) for k, v in parse_qsl(sanitize_bookings_return_qs(return_qs_form), keep_blank_values=False)]
    if notice:
        pairs.append(("notice", notice))
    if error:
        pairs.append(("error", error))
    if not pairs:
        return "/bookings"
    return "/bookings?" + urlencode(pairs)


def bookings_filter_qs_from_request(qp) -> str:
    pairs = []
    for k in sorted(_BOOKINGS_FILTER_KEYS):
        v = qp.get(k)
        if v:
            pairs.append((k, v))
    p = qp.get("page")
    if p:
        try:
            if int(p) > 1:
                pairs.append(("page", str(int(p))))
        except ValueError:
            pass
    return urlencode(pairs)


def bookings_export_qs_from_request(qp) -> str:
    pairs = []
    for k in sorted(_BOOKINGS_FILTER_KEYS):
        v = qp.get(k)
        if v:
            pairs.append((k, v))
    return urlencode(pairs)


def bookings_list_url(qp, page: int) -> str:
    pairs = []
    for k in sorted(_BOOKINGS_FILTER_KEYS):
        v = qp.get(k)
        if v:
            pairs.append((k, v))
    if page > 1:
        pairs.append(("page", str(page)))
    if not pairs:
        return "/bookings"
    return "/bookings?" + urlencode(pairs)


def bookings_list_query(db: Session, ctx: dict, user_data: dict, qp):
    filter_status = (qp.get("status") or "").strip().lower()
    filter_q = (qp.get("q") or "").strip()
    filter_college_id: Optional[int] = None
    if qp.get("college_id"):
        try:
            filter_college_id = int(qp.get("college_id"))
        except ValueError:
            filter_college_id = None
    filter_date_from = parse_iso_date_optional(qp.get("date_from"))
    filter_date_to = parse_iso_date_optional(qp.get("date_to"))

    q = db.query(models.Booking).options(
        joinedload(models.Booking.room).joinedload(models.Room.college),
        joinedload(models.Booking.user),
        joinedload(models.Booking.reviewer),
    )
    if not ctx["is_admin"]:
        q = q.filter(models.Booking.user_id == user_data["id"])
    else:
        if filter_status in ("pending", "confirmed", "cancelled"):
            q = q.filter(models.Booking.status == filter_status)
        if filter_college_id is not None and filter_college_id > 0:
            q = q.filter(models.Booking.room.has(models.Room.college_id == filter_college_id))
        if filter_date_from is not None:
            q = q.filter(models.Booking.starts_at >= datetime.combine(filter_date_from, datetime.min.time()))
        if filter_date_to is not None:
            q = q.filter(
                models.Booking.starts_at
                < datetime.combine(filter_date_to + timedelta(days=1), datetime.min.time())
            )
        if filter_q:
            pat = f"%{filter_q}%"
            q = q.filter(
                or_(
                    models.Booking.user.has(models.User.full_name.ilike(pat)),
                    models.Booking.user.has(models.User.email.ilike(pat)),
                )
            )

    return q.order_by(case((models.Booking.status == "pending", 0), else_=1), models.Booking.starts_at.desc())


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def normalize_email(email: str) -> str:
    return email.strip().lower()


_DATE_ISO_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
_TIME_HM_RE = re.compile(r"^\d{2}:\d{2}$")
_TIME_HMS_RE = re.compile(r"^\d{2}:\d{2}:\d{2}$")


def parse_booking_datetime(date_part: str, time_part: str) -> Optional[datetime]:
    """Только форматы из type=date и type=time (строго), без произвольного текста."""
    d = (date_part or "").strip()
    t = (time_part or "").strip()
    if not _DATE_ISO_RE.match(d):
        return None
    if _TIME_HM_RE.match(t):
        iso = f"{d}T{t}"
    elif _TIME_HMS_RE.match(t):
        iso = f"{d}T{t}"
    else:
        return None
    try:
        return datetime.fromisoformat(iso)
    except ValueError:
        return None


def parse_iso_date_optional(raw: Optional[str]) -> Optional[date]:
    if not raw:
        return None
    s = raw.strip()
    if not _DATE_ISO_RE.match(s):
        return None
    try:
        return date.fromisoformat(s)
    except ValueError:
        return None


def booking_dates_in_allowed_window(ds: str, de: str, today_d: date, max_d: date) -> bool:
    if not (_DATE_ISO_RE.match(ds) and _DATE_ISO_RE.match(de)):
        return False
    tmin = today_d.isoformat()
    tmax = max_d.isoformat()
    return tmin <= ds <= tmax and tmin <= de <= tmax


def booking_interval_overlap(
    db: Session,
    room_id: int,
    start: datetime,
    end: datetime,
    exclude_booking_id: Optional[int] = None,
) -> bool:
    q = db.query(models.Booking).filter(
        models.Booking.room_id == room_id,
        models.Booking.status != "cancelled",
        models.Booking.starts_at < end,
        models.Booking.ends_at > start,
    )
    if exclude_booking_id is not None:
        q = q.filter(models.Booking.id != exclude_booking_id)
    return q.first() is not None


def sync_room_status_from_bookings(db: Session, room_id: int) -> None:
    """Аудитория «занята», пока есть подтверждённая бронь с неистёкшим окончанием. Техобслуживание не трогаем."""
    room = db.query(models.Room).filter(models.Room.id == room_id).first()
    if not room:
        return
    if room.room_status == "maintenance" and room.is_under_maintenance:
        return
    now = datetime.now()
    has_confirmed = (
        db.query(models.Booking)
        .filter(
            models.Booking.room_id == room_id,
            models.Booking.status == "confirmed",
            models.Booking.ends_at > now,
        )
        .first()
        is not None
    )
    if has_confirmed:
        room.room_status = "occupied"
    else:
        room.room_status = "available"


def refresh_rooms_status_for_college(db: Session, college_id: int) -> None:
    """Обновляет статусы только у аудиторий, по которым уже есть записи заявок (история в БД)."""
    rooms = db.query(models.Room).filter(models.Room.college_id == college_id).all()
    for r in rooms:
        has_booking_row = (
            db.query(models.Booking).filter(models.Booking.room_id == r.id).first() is not None
        )
        if has_booking_row:
            sync_room_status_from_bookings(db, r.id)


def session_user_payload(u: models.User) -> dict:
    return {
        "id": u.id,
        "name": u.full_name,
        "email": u.email,
        "role": u.role,
    }


def seed_if_empty(db: Session):
    if db.query(models.College).first():
        return
    img1 = "https://images.unsplash.com/photo-1562774053-701939374585?w=900&q=80"
    img2 = "https://images.unsplash.com/photo-1541339907198-e08756dedf3f?w=900&q=80"
    c1 = models.College(
        name="Политехнический колледж",
        address="ул. Ленина, 10",
        image_url=img1,
        floor_plan_key="polytech",
    )
    c2 = models.College(
        name="Колледж информационных технологий",
        address="пр. Мира, 5",
        image_url=img2,
        floor_plan_key="cit",
    )
    db.add_all([c1, c2])
    db.commit()
    db.refresh(c1)
    db.refresh(c2)
    rooms_c1 = [
        models.Room(
            number="101",
            description="Лаборатория ИТ",
            capacity=25,
            college_id=c1.id,
            pos_x=23,
            pos_y=73,
            zone_w=17,
            zone_h=24,
            room_status="available",
        ),
        models.Room(
            number="105",
            description="Кабинет проектной работы",
            capacity=18,
            college_id=c1.id,
            pos_x=50,
            pos_y=73,
            zone_w=17,
            zone_h=24,
            room_status="occupied",
        ),
        models.Room(
            number="112",
            description="Методический кабинет",
            capacity=12,
            college_id=c1.id,
            pos_x=79,
            pos_y=23,
            zone_w=15,
            zone_h=20,
            room_status="maintenance",
            is_under_maintenance=True,
        ),
    ]
    rooms_c2 = [
        models.Room(
            number="202",
            description="Лекционный зал",
            capacity=50,
            college_id=c2.id,
            pos_x=58,
            pos_y=59,
            zone_w=52,
            zone_h=21,
            room_status="occupied",
        ),
        models.Room(
            number="210",
            description="Мультимедиа-аудитория",
            capacity=35,
            college_id=c2.id,
            pos_x=66,
            pos_y=38,
            zone_w=34,
            zone_h=13,
            room_status="available",
        ),
        models.Room(
            number="218",
            description="Переговорная",
            capacity=14,
            college_id=c2.id,
            pos_x=38,
            pos_y=38,
            zone_w=14,
            zone_h=13,
            room_status="maintenance",
            is_under_maintenance=True,
        ),
    ]
    db.add_all(rooms_c1 + rooms_c2)
    db.commit()


def staff_context(request: Request):
    user = request.session.get("user")
    role = user.get("role") if user else None
    return {
        "user": user,
        "role": role,
        "can_book": role in BOOKING_ROLES,
        "can_manage_maintenance": role in MAINTENANCE_ROLES,
        "is_admin": role == "admin",
    }


@app.get("/", response_class=HTMLResponse)
async def hub(request: Request, db: Session = Depends(get_db)):
    seed_if_empty(db)
    colleges = db.query(models.College).all()
    ctx = staff_context(request)
    ctx.update({"colleges": colleges, "request": request})
    return templates.TemplateResponse(request=request, name="hub.html", context=ctx)


@app.get("/college/{college_id}", response_class=HTMLResponse)
async def college_page(
    college_id: int,
    request: Request,
    db: Session = Depends(get_db),
    notice: Optional[str] = None,
    error: Optional[str] = None,
    booking_id: Optional[int] = None,
):
    college = db.query(models.College).filter(models.College.id == college_id).first()
    if not college:
        raise HTTPException(status_code=404, detail="Колледж не найден")
    refresh_rooms_status_for_college(db, college_id)
    db.commit()
    rooms = db.query(models.Room).filter(models.Room.college_id == college_id).all()

    def room_payload(r: models.Room) -> dict:
        st = (getattr(r, "room_status", None) or "available").lower()
        if st not in ("available", "occupied", "maintenance"):
            st = "available"
        return {
            "id": r.id,
            "number": r.number,
            "description": r.description,
            "capacity": r.capacity,
            "pos_x": r.pos_x,
            "pos_y": r.pos_y,
            "zone_w": getattr(r, "zone_w", None) or 14,
            "zone_h": getattr(r, "zone_h", None) or 20,
            "room_status": st,
            "is_under_maintenance": st == "maintenance" or bool(r.is_under_maintenance),
        }

    rooms_payload = [room_payload(r) for r in rooms]
    ctx = staff_context(request)
    floor_key = getattr(college, "floor_plan_key", None) or "polytech"
    if floor_key not in ("polytech", "cit"):
        floor_key = "polytech"

    today_iso = date.today().isoformat()
    max_book_iso = (date.today() + timedelta(days=366)).isoformat()

    ctx.update(
        {
            "college": college,
            "rooms": rooms,
            "floor_plan_key": floor_key,
            "rooms_json": json.dumps(rooms_payload, ensure_ascii=False),
            "notice": notice,
            "error": error,
            "booking_id": booking_id,
            "today_iso": today_iso,
            "max_book_iso": max_book_iso,
            "request": request,
        }
    )
    return templates.TemplateResponse(request=request, name="college.html", context=ctx)


@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    if request.session.get("user"):
        return RedirectResponse(url="/", status_code=303)
    error = request.query_params.get("error")
    next_url = request.query_params.get("next") or ""
    return templates.TemplateResponse(
        request=request,
        name="login.html",
        context={"request": request, "error": error, "next_url": next_url},
    )


@app.post("/login")
async def login_submit(
    request: Request,
    db: Session = Depends(get_db),
    csrf_token: str = Form(""),
    email: str = Form(...),
    password: str = Form(...),
    next_url: str = Form(""),
):
    if not validate_csrf_token(request, csrf_token):
        params = {"error": "csrf"}
        if next_url.strip():
            params["next"] = next_url.strip()
        return RedirectResponse(url=f"/login?{urlencode(params)}", status_code=303)
    email_n = normalize_email(email)
    user = db.query(models.User).filter(models.User.email == email_n).first()
    if not user or not auth_utils.verify_password(password, user.password_hash):
        params = {"error": "bad_credentials"}
        if next_url.strip():
            params["next"] = next_url.strip()
        return RedirectResponse(url=f"/login?{urlencode(params)}", status_code=303)

    if user.role not in STAFF_ROLES:
        params = {"error": "forbidden_role"}
        if next_url.strip():
            params["next"] = next_url.strip()
        return RedirectResponse(url=f"/login?{urlencode(params)}", status_code=303)

    request.session["user"] = session_user_payload(user)
    dest = next_url.strip() or "/"
    if not dest.startswith("/"):
        dest = "/"
    return RedirectResponse(url=dest, status_code=303)


@app.get("/register", response_class=HTMLResponse)
async def register_page(request: Request):
    if request.session.get("user"):
        return RedirectResponse(url="/", status_code=303)
    error = request.query_params.get("error")
    return templates.TemplateResponse(
        request=request,
        name="register.html",
        context={"request": request, "error": error},
    )


@app.post("/register")
async def register_submit(
    request: Request,
    db: Session = Depends(get_db),
    csrf_token: str = Form(""),
    full_name: str = Form(...),
    email: str = Form(...),
    password: str = Form(...),
    role: str = Form(...),
):
    if not validate_csrf_token(request, csrf_token):
        return RedirectResponse(url="/register?error=csrf", status_code=303)
    if role not in STAFF_ROLES:
        return RedirectResponse(url="/register?error=invalid_role", status_code=303)
    if len(password) < 6:
        return RedirectResponse(url="/register?error=weak_password", status_code=303)
    email_n = normalize_email(email)
    user = models.User(
        full_name=full_name.strip(),
        email=email_n,
        password_hash=auth_utils.hash_password(password),
        role=role,
    )
    db.add(user)
    try:
        db.commit()
        db.refresh(user)
    except IntegrityError:
        db.rollback()
        return RedirectResponse(url="/register?error=exists", status_code=303)

    request.session["user"] = session_user_payload(user)
    return RedirectResponse(url="/", status_code=303)


@app.get("/logout")
async def logout(request: Request):
    request.session.clear()
    return RedirectResponse(url="/")


@app.get("/bookings", response_class=HTMLResponse)
async def bookings_list(request: Request, db: Session = Depends(get_db), notice: Optional[str] = None, error: Optional[str] = None):
    ctx = staff_context(request)
    user_data = ctx.get("user")
    if not user_data or user_data.get("role") not in STAFF_ROLES:
        return RedirectResponse(url="/login?next=/bookings", status_code=303)

    qp = request.query_params
    filter_status = (qp.get("status") or "").strip().lower()
    filter_q = (qp.get("q") or "").strip()
    filter_college_id: Optional[int] = None
    if qp.get("college_id"):
        try:
            filter_college_id = int(qp.get("college_id"))
        except ValueError:
            filter_college_id = None
    filter_date_from = parse_iso_date_optional(qp.get("date_from"))
    filter_date_to = parse_iso_date_optional(qp.get("date_to"))

    try:
        page = max(1, int(qp.get("page") or 1))
    except ValueError:
        page = 1

    q = bookings_list_query(db, ctx, user_data, qp)
    total_count = q.count()
    total_pages = max(1, (total_count + BOOKINGS_PER_PAGE - 1) // BOOKINGS_PER_PAGE) if total_count else 1
    page = min(page, total_pages)
    bookings = q.offset((page - 1) * BOOKINGS_PER_PAGE).limit(BOOKINGS_PER_PAGE).all()

    colleges = (
        db.query(models.College).order_by(models.College.name)
        if ctx["is_admin"]
        else []
    )

    export_qs = bookings_export_qs_from_request(qp)
    export_csv_url = "/bookings/export.csv" + ("?" + export_qs if export_qs else "")

    ctx.update(
        {
            "request": request,
            "bookings": bookings,
            "notice": notice,
            "error": error,
            "colleges": colleges,
            "filter_status": filter_status,
            "filter_college_id": filter_college_id,
            "filter_date_from": filter_date_from.isoformat() if filter_date_from else "",
            "filter_date_to": filter_date_to.isoformat() if filter_date_to else "",
            "filter_q": filter_q,
            "filter_return_qs": bookings_filter_qs_from_request(qp),
            "page": page,
            "total_pages": total_pages,
            "total_count": total_count,
            "per_page": BOOKINGS_PER_PAGE,
            "pagination_prev_url": bookings_list_url(qp, page - 1) if page > 1 else None,
            "pagination_next_url": bookings_list_url(qp, page + 1) if page < total_pages else None,
            "export_csv_url": export_csv_url,
        }
    )
    return templates.TemplateResponse(request=request, name="bookings.html", context=ctx)


@app.get("/bookings/export.csv")
async def bookings_export_csv(request: Request, db: Session = Depends(get_db)):
    ctx = staff_context(request)
    user_data = ctx.get("user")
    if not user_data or user_data.get("role") not in STAFF_ROLES:
        return RedirectResponse(url="/login?next=/bookings/export.csv", status_code=303)
    if not ctx["is_admin"]:
        return RedirectResponse(url="/bookings?error=forbidden", status_code=303)

    qp = request.query_params
    q = bookings_list_query(db, ctx, user_data, qp)
    rows = q.all()

    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(
        [
            "id",
            "college",
            "room",
            "starts_at",
            "ends_at",
            "status",
            "applicant_name",
            "applicant_email",
            "reviewer_name",
            "reviewed_at",
        ]
    )
    for b in rows:
        rev_name = b.reviewer.full_name if b.reviewer else ""
        rev_at = b.reviewed_at.isoformat(sep=" ", timespec="minutes") if b.reviewed_at else ""
        w.writerow(
            [
                b.id,
                b.room.college.name if b.room and b.room.college else "",
                b.room.number if b.room else "",
                b.starts_at.isoformat(sep=" ", timespec="minutes"),
                b.ends_at.isoformat(sep=" ", timespec="minutes"),
                b.status,
                b.user.full_name if b.user else "",
                b.user.email if b.user else "",
                rev_name,
                rev_at,
            ]
        )

    body = "\ufeff" + buf.getvalue()
    fname = f"bookings_{date.today().isoformat()}.csv"
    return Response(
        content=body.encode("utf-8"),
        media_type="text/csv; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="{fname}"'},
    )


@app.post("/bookings/{booking_id}/cancel")
async def booking_cancel(
    booking_id: int,
    request: Request,
    db: Session = Depends(get_db),
    csrf_token: str = Form(""),
    return_qs: str = Form(""),
):
    if not validate_csrf_token(request, csrf_token):
        return RedirectResponse(url=bookings_redirect_url(return_qs, error="csrf"), status_code=303)
    ctx = staff_context(request)
    user_data = ctx.get("user")
    if not user_data:
        return RedirectResponse(url="/login?next=/bookings", status_code=303)

    b = db.query(models.Booking).filter(models.Booking.id == booking_id).first()
    if not b:
        return RedirectResponse(url=bookings_redirect_url(return_qs, error="not_found"), status_code=303)
    if not ctx["is_admin"] and b.user_id != user_data["id"]:
        return RedirectResponse(url=bookings_redirect_url(return_qs, error="forbidden"), status_code=303)
    if b.status != "cancelled":
        rid = b.room_id
        b.status = "cancelled"
        db.commit()
        sync_room_status_from_bookings(db, rid)
        db.commit()
    return RedirectResponse(url=bookings_redirect_url(return_qs, notice="cancelled"), status_code=303)


@app.post("/bookings/{booking_id}/confirm")
async def booking_confirm(
    booking_id: int,
    request: Request,
    db: Session = Depends(get_db),
    csrf_token: str = Form(""),
    return_qs: str = Form(""),
):
    if not validate_csrf_token(request, csrf_token):
        return RedirectResponse(url=bookings_redirect_url(return_qs, error="csrf"), status_code=303)
    ctx = staff_context(request)
    if not ctx.get("is_admin"):
        return RedirectResponse(url=bookings_redirect_url(return_qs, error="forbidden"), status_code=303)
    user_data = request.session.get("user") or {}

    b = db.query(models.Booking).filter(models.Booking.id == booking_id).first()
    if not b:
        return RedirectResponse(url=bookings_redirect_url(return_qs, error="not_found"), status_code=303)
    if b.status != "pending":
        return RedirectResponse(url=bookings_redirect_url(return_qs, error="bad_state"), status_code=303)

    room = db.query(models.Room).filter(models.Room.id == b.room_id).first()
    if room and (room.room_status == "maintenance" or room.is_under_maintenance):
        return RedirectResponse(url=bookings_redirect_url(return_qs, error="room_maintenance"), status_code=303)

    if booking_interval_overlap(db, b.room_id, b.starts_at, b.ends_at, exclude_booking_id=b.id):
        return RedirectResponse(url=bookings_redirect_url(return_qs, error="overlap"), status_code=303)

    admin_id = int(user_data["id"])
    b.status = "confirmed"
    b.reviewed_at = datetime.now()
    b.reviewed_by_id = admin_id
    db.commit()
    sync_room_status_from_bookings(db, b.room_id)
    db.commit()
    return RedirectResponse(url=bookings_redirect_url(return_qs, notice="confirmed"), status_code=303)


@app.post("/college/{college_id}/room/{room_id}/maintenance")
async def set_room_maintenance(
    college_id: int,
    room_id: int,
    request: Request,
    db: Session = Depends(get_db),
    csrf_token: str = Form(""),
    under_maintenance: str = Form("0"),
):
    if not validate_csrf_token(request, csrf_token):
        return RedirectResponse(url=f"/college/{college_id}?error=csrf", status_code=303)
    user = request.session.get("user")
    role = user.get("role") if user else None
    if role not in MAINTENANCE_ROLES:
        raise HTTPException(status_code=403, detail="Недостаточно прав")
    room = (
        db.query(models.Room)
        .filter(models.Room.id == room_id, models.Room.college_id == college_id)
        .first()
    )
    if not room:
        raise HTTPException(status_code=404, detail="Аудитория не найдена")
    on = under_maintenance in ("1", "on", "true", "True")
    if on:
        room.room_status = "maintenance"
        room.is_under_maintenance = True
    else:
        room.is_under_maintenance = False
        if getattr(room, "room_status", "") == "maintenance":
            room.room_status = "available"
    db.commit()
    return RedirectResponse(url=f"/college/{college_id}?notice=maintenance_updated", status_code=303)


@app.post("/college/{college_id}/room/{room_id}/book-request")
async def book_request(
    college_id: int,
    room_id: int,
    request: Request,
    db: Session = Depends(get_db),
    csrf_token: str = Form(""),
    date_start: str = Form(""),
    time_start: str = Form(""),
    date_end: str = Form(""),
    time_end: str = Form(""),
):
    if not validate_csrf_token(request, csrf_token):
        return RedirectResponse(url=f"/college/{college_id}?error=csrf", status_code=303)
    sess = request.session.get("user")
    role = sess.get("role") if sess else None
    user_id = sess.get("id") if sess else None
    if role not in BOOKING_ROLES or user_id is None:
        return RedirectResponse(url=f"/college/{college_id}?error=need_staff_login", status_code=303)

    room = (
        db.query(models.Room)
        .filter(models.Room.id == room_id, models.Room.college_id == college_id)
        .first()
    )
    if not room:
        raise HTTPException(status_code=404, detail="Аудитория не найдена")

    st = (getattr(room, "room_status", "") or "available").lower()
    if st == "maintenance" or room.is_under_maintenance:
        return RedirectResponse(url=f"/college/{college_id}?error=room_maintenance", status_code=303)
    if st == "occupied":
        return RedirectResponse(url=f"/college/{college_id}?error=room_occupied", status_code=303)

    ds = (date_start or "").strip()
    de = (date_end or "").strip()
    today_d = date.today()
    max_d = today_d + timedelta(days=366)
    if not booking_dates_in_allowed_window(ds, de, today_d, max_d):
        return RedirectResponse(url=f"/college/{college_id}?error=bad_slot", status_code=303)

    start = parse_booking_datetime(ds, (time_start or "").strip())
    end = parse_booking_datetime(de, (time_end or "").strip())
    if not start or not end or end <= start:
        return RedirectResponse(url=f"/college/{college_id}?error=bad_slot", status_code=303)

    if booking_interval_overlap(db, room_id, start, end):
        return RedirectResponse(url=f"/college/{college_id}?error=slot_overlap", status_code=303)

    booking = models.Booking(
        room_id=room_id,
        user_id=int(user_id),
        starts_at=start,
        ends_at=end,
        status="pending",
    )
    db.add(booking)
    db.commit()
    db.refresh(booking)
    return RedirectResponse(
        url=f"/college/{college_id}?notice=book_saved&booking_id={booking.id}",
        status_code=303,
    )


