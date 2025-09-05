# app.py
from __future__ import annotations

# ============== Stdlib ==============
from pathlib import Path
from datetime import datetime, timedelta
import io
import os
import smtplib
import ssl
from email.message import EmailMessage
from functools import wraps
from typing import Optional, Tuple

# ============= 3rd Party ============
import numpy as np
import pandas as pd
import matplotlib
matplotlib.use("Agg")  # Sunucu tarafı render
import matplotlib.pyplot as plt
from dotenv import load_dotenv
from flask import (
    Flask, request, render_template, redirect, url_for,
    flash, abort, send_file, make_response
)
from flask_sqlalchemy import SQLAlchemy
from flask_login import (
    LoginManager, login_user, login_required, logout_user,
    current_user, UserMixin
)
from flask.cli import with_appcontext
import click

from sqlalchemy import or_

# ============ Uygulama Ayarları ============
load_dotenv()
BASE_DIR = Path(__file__).resolve().parent

app = Flask(__name__)
app.config.update(
    SECRET_KEY=os.getenv("SECRET_KEY", "dev-secret-change-me"),
    SQLALCHEMY_DATABASE_URI=f"sqlite:///{BASE_DIR / 'database.db'}",
    SQLALCHEMY_TRACK_MODIFICATIONS=False,
)

db = SQLAlchemy(app)

login_manager = LoginManager(app)
login_manager.login_view = "login"  # @login_required yönlendirme hedefi                                                # type: ignore
login_manager.login_message = "Giriş yapmalısınız."

# Sabitler
STATUSES = {"açık", "işlem sürecinde", "kapalı"}
PRIORITIES = {"düşük", "normal", "yüksek"}

# ================ Modeller ================
class HelpDesk(db.Model):
    __tablename__ = "helpdesk_tickets"
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), nullable=False)
    subject = db.Column(db.String(120), nullable=False)
    description = db.Column(db.Text, nullable=False)
    priority = db.Column(db.String(10), default="normal")     # düşük|normal|yüksek
    status = db.Column(db.String(20), default="açık")         # açık|işlem sürecinde|kapalı
    created_by = db.Column(db.String(120), nullable=True)     # oluşturucu e-posta
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    pending_delete_at = db.Column(db.DateTime, nullable=True) # kapandıktan sonra silinme zamanı

    def __repr__(self) -> str:
        return f"<HelpDesk {self.id}: {self.subject}>"

class HelpDeskArchive(db.Model):
    __tablename__ = "helpdesk_archive"
    id = db.Column(db.Integer, primary_key=True)
    orig_id = db.Column(db.Integer, nullable=False)
    username = db.Column(db.String(80), nullable=False)
    subject = db.Column(db.String(120), nullable=False)
    description = db.Column(db.Text, nullable=False)
    priority = db.Column(db.String(10))
    status = db.Column(db.String(20))
    created_by = db.Column(db.String(120))
    created_at = db.Column(db.DateTime)
    updated_at = db.Column(db.DateTime)
    deleted_at = db.Column(db.DateTime, default=datetime.utcnow)

class User(UserMixin, db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), default="user")  # admin | user
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def set_password(self, password: str) -> None:
        from werkzeug.security import generate_password_hash
        self.password_hash = generate_password_hash(password)

    def check_password(self, password: str) -> bool:
        from werkzeug.security import check_password_hash
        return check_password_hash(self.password_hash, password)

    def __repr__(self) -> str:
        return f"<User {self.email}>"


# ================ Modeller (envanter) ================
class InventoryAsset(db.Model):
    __tablename__ = "inventory_assets"
    id = db.Column(db.Integer, primary_key=True)
    hostname = db.Column(db.String(120), nullable=False)
    assigned_to = db.Column(db.String(120), nullable=True)   # kullanıcı e-posta ya da ad
    os = db.Column(db.String(80), nullable=True)             # Windows 11, Ubuntu 22.04 vs.
    cpu = db.Column(db.String(120), nullable=True)
    ram_gb = db.Column(db.Integer, nullable=True)
    disk_gb = db.Column(db.Integer, nullable=True)
    ip = db.Column(db.String(64), nullable=True)
    mac = db.Column(db.String(64), nullable=True)
    location = db.Column(db.String(120), nullable=True)      # Ofis/Şube
    status = db.Column(db.String(20), default="active")      # active | retired | repair
    last_seen = db.Column(db.DateTime, default=datetime.utcnow)

    def __repr__(self) -> str:
        return f"<Inv {self.hostname} ({self.os})>"
    

# ============== Login yardımcıları ==============
@login_manager.user_loader
def load_user(user_id: str) -> Optional[User]:
    return User.query.get(int(user_id))

def is_admin() -> bool:
    return current_user.is_authenticated and current_user.role == "admin"

def admin_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if not is_admin():
            abort(403, description="Bu işlem için admin yetkisi gerekir.")
        return f(*args, **kwargs)
    return wrapper

def tickets_q_for_current_user():
    """
    Admin: tüm kayıtları görür;
    User : sadece kendisinin oluşturduğu kayıtları görür.
    """
    return HelpDesk.query if is_admin() else HelpDesk.query.filter(HelpDesk.created_by == current_user.email)

# ============== Yardımcılar ==============
def ensure_data_folder() -> None:
    """data/ klasörünü ve örnek CSV'leri garanti eder."""
    data_dir = BASE_DIR / "data"
    data_dir.mkdir(exist_ok=True)

    stoklar_path = data_dir / "stoklar.csv"
    siparisler_path = data_dir / "siparisler.csv"

    if not stoklar_path.exists():
        pd.DataFrame({
            "malzeme_kodu": ["M001", "M002", "M003", "M004"],
            "malzeme_adi":  ["Çelik Profil", "Alüminyum Levha", "Plastik Boru", "Cam Panel"],
            "miktar":       [150, 75, 200, 30],
            "birim":        ["kg", "m²", "m", "adet"],
            "tarih":        ["2024-01-15", "2024-01-16", "2024-01-17", "2024-01-18"],
        }).to_csv(stoklar_path, index=False)

    if not siparisler_path.exists():
        pd.DataFrame({
            "siparis_no": ["SIP001", "SIP002", "SIP003", "SIP004"],
            "musteri":    ["ABC Şirketi", "XYZ Ltd", "DEF Holding", "GHI A.Ş."],
            "tarih":      ["2024-01-15", "2024-01-16", "2024-01-17", "2024-01-18"],
            "tutar":      [15000, 8500, 22000, 12500],
        }).to_csv(siparisler_path, index=False)

def send_mail(to_email: str, subject: str, body: str) -> bool:
    """Basit SMTP gönderimi. Eksik ayar/hata durumunda uygulamayı durdurmaz."""
    host = os.getenv("SMTP_HOST")
    port = int(os.getenv("SMTP_PORT", "587"))
    user = os.getenv("SMTP_USER")
    pwd  = os.getenv("SMTP_PASS")
    sender = os.getenv("MAIL_SENDER", user)
    use_tls = (os.getenv("MAIL_USE_TLS", "true").lower() == "true")
    if not (host and port and user and pwd and to_email):
        print("[mail] Eksik SMTP ayarı veya alıcı yok, gönderim atlandı.")
        return False

    msg = EmailMessage()
    msg["From"] = sender
    msg["To"] = to_email
    msg["Subject"] = subject
    msg.set_content(body)

    try:
        if use_tls:
            with smtplib.SMTP(host, port) as s:
                s.ehlo(); s.starttls(context=ssl.create_default_context())
                s.login(user, pwd); s.send_message(msg)
        else:
            with smtplib.SMTP_SSL(host, port, context=ssl.create_default_context()) as s:
                s.login(user, pwd); s.send_message(msg)
        print(f"[mail] Gönderildi -> {to_email} / {subject}")
        return True
    except Exception as e:
        print(f"[mail] Gönderilemedi: {e}")
        return False

def _fig_to_png_bytes(fig) -> io.BytesIO:
    """Matplotlib figürünü PNG byte stream'e çevirir."""
    buf = io.BytesIO()
    fig.savefig(buf, format="png", bbox_inches="tight", dpi=144)
    plt.close(fig)
    buf.seek(0)
    return buf

# ============== Auth ==============
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = (request.form.get("email") or "").strip().lower()
        password = (request.form.get("password") or "")
        if not email or not password:
            flash("E-posta ve parola boş olamaz.", "danger")
            return redirect(url_for("login"))

        user = User.query.filter_by(email=email).first()
        if user and user.check_password(password):
            login_user(user)
            flash("Giriş başarılı.", "success")
            return redirect(request.args.get("next") or url_for("home"))
        flash("E-posta veya parola hatalı.", "danger")
    return render_template("login.html")

@app.route("/logout")
@login_required
def logout():
    logout_user()
    flash("Çıkış yapıldı.", "info")
    return redirect(url_for("login"))

# ============== Dashboard ==============
@app.route("/")
@login_required
def home():
   
    ensure_data_folder()

    q = tickets_q_for_current_user()

    # Admin için özet sayımlar; user için maliyetsiz bırakıyoruz
    total = open_c = in_prog = closed = None
    if is_admin():
        try:
            total   = q.count()
            open_c  = q.filter_by(status="open").count()
            in_prog = q.filter_by(status="in_progress").count()
            closed  = q.filter_by(status="closed").count()
        except Exception as e:
            # Eski veri/kolon uyumsuzluklarında UI tarafında None gösterilir
            print(f"[home] Özet kart sayımları hesaplanamadı: {e}")

    # Son 5
    try:
        recent = q.order_by(HelpDesk.created_at.desc()).limit(5).all()
    except Exception:
        recent = q.order_by(HelpDesk.id.desc()).limit(5).all()

    # CSV özet
    stok_rows = siparis_rows = None
    stok_path = BASE_DIR / "data" / "stoklar.csv"
    sip_path  = BASE_DIR / "data" / "siparisler.csv"
    try:
        if stok_path.exists():
            stok_rows = len(pd.read_csv(stok_path))
    except Exception as e:
        print(f"[csv] Stok okuma: {e}"); stok_rows = 0
    try:
        if sip_path.exists():
            siparis_rows = len(pd.read_csv(sip_path))
    except Exception as e:
        print(f"[csv] Sipariş okuma: {e}"); siparis_rows = 0

    return render_template(
        "index.html",
        total=total, open_c=open_c, in_prog=in_prog, closed=closed,
        recent=recent, stok_rows=stok_rows, siparis_rows=siparis_rows,
    )

# ============== SAP Raporları ==============
def _read_sap_csvs() -> Tuple[pd.DataFrame, pd.DataFrame]:
    ensure_data_folder()
    d = BASE_DIR / "data"
    stoklar_path = d / "stoklar.csv"
    siparisler_path = d / "siparisler.csv"
    if not (stoklar_path.exists() and siparisler_path.exists()):
        abort(404, description="Rapor dosyaları bulunamadı. data/ klasörünü kontrol edin.")
    return pd.read_csv(stoklar_path), pd.read_csv(siparisler_path)

def _apply_filters(stoklar_df: pd.DataFrame, siparisler_df: pd.DataFrame) -> Tuple[pd.DataFrame, pd.DataFrame]:
    # tarihleri datetime'a çevir
    for name, df in [("stoklar", stoklar_df), ("siparisler", siparisler_df)]:
        if "tarih" in df.columns:
            try:
                df["tarih"] = pd.to_datetime(df["tarih"], errors="coerce")
            except Exception as e:
                print(f"[rapor] {name} tarih dönüştürme: {e}")

    start = request.args.get("start")
    end   = request.args.get("end")
    musteri  = (request.args.get("musteri") or "").strip()
    malzeme  = (request.args.get("malzeme") or "").strip()

    if start:
        try:
            sdt = pd.to_datetime(start, errors="coerce")
            if pd.notna(sdt):
                if "tarih" in stoklar_df.columns:    stoklar_df = stoklar_df[stoklar_df["tarih"] >= sdt]
                if "tarih" in siparisler_df.columns: siparisler_df = siparisler_df[siparisler_df["tarih"] >= sdt]
        except Exception as e:
            print(f"[rapor] start filtresi: {e}")

    if end:
        try:
            edt = pd.to_datetime(end, errors="coerce") + pd.Timedelta(days=1)
            if pd.notna(edt):
                if "tarih" in stoklar_df.columns:    stoklar_df = stoklar_df[stoklar_df["tarih"] < edt]
                if "tarih" in siparisler_df.columns: siparisler_df = siparisler_df[siparisler_df["tarih"] < edt]
        except Exception as e:
            print(f"[rapor] end filtresi: {e}")

    if musteri and "musteri" in siparisler_df.columns:
        try:
            m = siparisler_df["musteri"].astype(str).str.contains(musteri, case=False, na=False)
            siparisler_df = siparisler_df[m]
        except Exception as e:
            print(f"[rapor] musteri filtresi: {e}")

    if malzeme and {"malzeme_kodu", "malzeme_adi"}.issubset(stoklar_df.columns):
        try:
            mk = stoklar_df["malzeme_kodu"].astype(str).str.contains(malzeme, case=False, na=False)
            ma = stoklar_df["malzeme_adi"].astype(str).str.contains(malzeme, case=False, na=False)
            stoklar_df = stoklar_df[mk | ma]
        except Exception as e:
            print(f"[rapor] malzeme filtresi: {e}")

    # Görünüm için tarihi string'e çevir
    for df in (stoklar_df, siparisler_df):
        if "tarih" in df.columns:
            try:
                df["tarih"] = df["tarih"].dt.strftime("%Y-%m-%d")
            except Exception as e:
                print(f"[rapor] tarih format: {e}")
    return stoklar_df, siparisler_df

@app.route("/raporlar")
@login_required
def raporlar():
    try:
        stoklar_df, siparisler_df = _apply_filters(*_read_sap_csvs())
    except Exception as e:
        flash(f"CSV dosyaları okunamadı: {e}", "danger")
        return redirect(url_for("home"))

    return render_template(
        "raporlar.html",
        stoklar=stoklar_df.to_dict(orient="records"),
        siparisler=siparisler_df.to_dict(orient="records"),
    )

@app.route("/raporlar/export/<string:fmt>")
@login_required
def raporlar_export(fmt: str):
    if fmt.lower() != "xlsx":
        abort(400, description="Sadece Excel (xlsx) export destekleniyor.")

    try:
        stoklar_df, siparisler_df = _apply_filters(*_read_sap_csvs())
    except Exception as e:
        flash(f"CSV dosyaları okunamadı: {e}", "danger")
        return redirect(url_for("raporlar"))

    # Excel yaz
    output = io.BytesIO()
    try:
        with pd.ExcelWriter(output, engine="openpyxl") as writer:
            stoklar_df.to_excel(writer, sheet_name="Stoklar", index=False)
            siparisler_df.to_excel(writer, sheet_name="Siparisler", index=False)
        output.seek(0)
        return send_file(
            output, as_attachment=True, download_name="sap_rapor.xlsx",
            mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        )
    except Exception as e:
        flash(f"Excel dosyası oluşturulamadı: {e}", "danger")
        return redirect(url_for("raporlar"))

# ============== Otomatik arşivleme (kapalıları sil) ==============
@app.before_request
def purge_expired_tickets():
    """Sadece kapanmış ve silinme zamanı gelen ticket’ları arşivler; hiçbir template döndürmez."""
    try:
        now = datetime.utcnow()
        expired = HelpDesk.query.filter(
            HelpDesk.status == "kapalı",
            HelpDesk.pending_delete_at.isnot(None),
            HelpDesk.pending_delete_at <= now
        ).all()
        for t in expired:
            db.session.add(HelpDeskArchive(
                orig_id=t.id, username=t.username, subject=t.subject,                                                  # type: ignore  
                description=t.description, priority=t.priority, status=t.status,                                       # type: ignore      
                created_by=t.created_by, created_at=t.created_at, updated_at=t.updated_at                                # type: ignore
            ))
            db.session.delete(t)
        if expired:
            db.session.commit()
    except Exception as e:
        db.session.rollback()
        print(f"[purge] Hata: {e}")
    # ÖNEMLİ: return YOK

@app.route("/api/inventory/ingest", methods=["POST"])
@login_required
@admin_required
def inventory_ingest():
    """
    Basit ingest: JSON gövdesiyle gelen cihazı ekler/günceller.
    Demo ajan simülasyonu için:
    curl -X POST -H "Content-Type: application/json" -b cookiejar \
      -d '{"hostname":"PC-101","assigned_to":"ali@firma.com","os":"Windows 11","cpu":"i5-11400","ram_gb":16,"disk_gb":512,"ip":"10.0.0.5","mac":"00:11:22:33:44:55","location":"İstanbul","status":"active"}' \
      http://localhost:5000/api/inventory/ingest
    """
    data = request.get_json(silent=True) or {}
    hostname = (data.get("hostname") or "").strip()
    if not hostname:
        return make_response({"ok": False, "error": "hostname zorunlu"}, 400)

    asset = InventoryAsset.query.filter_by(hostname=hostname).first()
    if not asset:
        asset = InventoryAsset(hostname=hostname)                                                                   # type: ignore

    # Güncelle
    for k in ["assigned_to","os","cpu","ip","mac","location","status"]:
        v = data.get(k)
        setattr(asset, k, v if (v is not None and str(v).strip() != "") else getattr(asset, k))

    for k in ["ram_gb","disk_gb"]:
        v = data.get(k)
        if v is not None:
            try:
                setattr(asset, k, int(v))
            except Exception:
                pass

    asset.last_seen = datetime.utcnow()
    db.session.add(asset); db.session.commit()
    return {"ok": True, "id": asset.id}

# ============== Envanter ==============
@app.route("/inventory")
@login_required
@admin_required
def inventory_list():
    q = InventoryAsset.query

    # Basit filtreler (navbar search'ten bağımsız sayfa içi filtre)
    term = (request.args.get("q") or "").strip()
    status = (request.args.get("status") or "").strip()
    os_name = (request.args.get("os") or "").strip()

    if term:
        like = f"%{term}%"
        q = q.filter(
            or_(
                InventoryAsset.hostname.ilike(like),
                InventoryAsset.assigned_to.ilike(like),
                InventoryAsset.ip.ilike(like),
                InventoryAsset.location.ilike(like),
            )
        )
    if status:
        q = q.filter_by(status=status)
    if os_name:
        q = q.filter(InventoryAsset.os.ilike(f"%{os_name}%"))

    assets = q.order_by(InventoryAsset.hostname.asc()).all()
    return render_template("inventory_list.html", assets=assets, term=term, status=status, os_name=os_name)

@app.route("/inventory/new", methods=["GET", "POST"])
@login_required
@admin_required
def inventory_new():
    if request.method == "POST":
        hostname = (request.form.get("hostname") or "").strip()
        assigned_to = (request.form.get("assigned_to") or "").strip()
        os_name = (request.form.get("os") or "").strip()
        cpu = (request.form.get("cpu") or "").strip()
        ram_gb = request.form.get("ram_gb") or None
        disk_gb = request.form.get("disk_gb") or None
        ip = (request.form.get("ip") or "").strip()
        mac = (request.form.get("mac") or "").strip()
        location = (request.form.get("location") or "").strip()
        status = (request.form.get("status") or "active").strip()

        if not hostname:
            flash("Hostname zorunludur.", "danger")
            return render_template("inventory_new.html")

        try:
            asset = InventoryAsset(
                hostname=hostname, assigned_to=assigned_to or None,                                                 # type: ignore
                os=os_name or None, cpu=cpu or None,                                                     # type: ignore                             
                ram_gb=int(ram_gb) if ram_gb else None,                                                         # type: ignore
                disk_gb=int(disk_gb) if disk_gb else None,                                               # type: ignore                         
                ip=ip or None, mac=mac or None, location=location or None,                            # type: ignore                            
                status=status or "active", last_seen=datetime.utcnow()                                       # type: ignore                         
            )
            db.session.add(asset); db.session.commit()
            flash("Cihaz eklendi.", "success")
            return redirect(url_for("inventory_list"))
        except Exception as e:
            db.session.rollback()
            flash(f"Cihaz eklenemedi: {e}", "danger")

    return render_template("inventory_new.html")


@app.route("/search")
@login_required
def search():
    term = (request.args.get("q") or "").strip()
    if not term:
        flash("Arama yapmak için bir anahtar kelime yazın.", "warning")
        return redirect(url_for("home"))

    # --- HelpDesk (rol bazlı görünürlük korunur)
    tq = tickets_q_for_current_user().filter(
        or_(
            HelpDesk.subject.ilike(f"%{term}%"),
            HelpDesk.description.ilike(f"%{term}%"),
            HelpDesk.username.ilike(f"%{term}%"),
        )
    )
    try:
        tickets = tq.order_by(HelpDesk.created_at.desc()).limit(50).all()
    except Exception:
        tickets = tq.order_by(HelpDesk.id.desc()).limit(50).all()
    ticket_count = len(tickets)

    # --- SAP CSV'ler
    ensure_data_folder()
    d = BASE_DIR / "data"
    stok_df = pd.read_csv(d / "stoklar.csv") if (d / "stoklar.csv").exists() else pd.DataFrame()
    sip_df  = pd.read_csv(d / "siparisler.csv") if (d / "siparisler.csv").exists() else pd.DataFrame()

    def _df_contains(df: pd.DataFrame, cols: list[str], t: str) -> pd.DataFrame:
        if df.empty: return df
        mask = None
        for c in cols:
            if c in df.columns:
                m = df[c].astype(str).str.contains(t, case=False, na=False)
                mask = m if mask is None else (mask | m)
        return df[mask] if mask is not None else pd.DataFrame()

    stok_hits = _df_contains(stok_df, ["malzeme_kodu", "malzeme_adi", "birim"], term)
    sip_hits  = _df_contains(sip_df,  ["siparis_no", "musteri"], term)

    for df in (stok_hits, sip_hits):
        if "tarih" in df.columns:
            try:
                df["tarih"] = pd.to_datetime(df["tarih"], errors="coerce").dt.strftime("%Y-%m-%d")
            except Exception:
                pass

    stok_results    = stok_hits.head(50).to_dict(orient="records")
    siparis_results = sip_hits.head(50).to_dict(orient="records")
    stok_count      = len(stok_hits)
    siparis_count   = len(sip_hits)

    # --- Envanter (varsa)
    inventory_results = []
    inventory_count = 0
    if is_admin():
        try:
            inv_q = InventoryAsset.query.filter(
                or_(
                    InventoryAsset.hostname.ilike(f"%{term}%"),
                    InventoryAsset.assigned_to.ilike(f"%{term}%"),
                    InventoryAsset.ip.ilike(f"%{term}%"),
                    InventoryAsset.location.ilike(f"%{term}%"),
                    InventoryAsset.os.ilike(f"%{term}%"),
                    InventoryAsset.cpu.ilike(f"%{term}%"),
                )
            ).order_by(InventoryAsset.hostname.asc()).limit(50)
            inventory_results = inv_q.all()
            inventory_count = len(inventory_results)
        except Exception as e:
            # Model yoksa problem değil; envanter bölümünü boş göstereceğiz
            print(f"[search] Inventory skip: {e}")

    return render_template(
        "search.html",
        q=term,
        # HelpDesk
        tickets=tickets, ticket_count=ticket_count,
        # SAP
        stok_results=stok_results, siparis_results=siparis_results,
        stok_count=stok_count, siparis_count=siparis_count,
        # Inventory
        inventory_results=inventory_results, inventory_count=inventory_count,
    )

# ============== Help Desk ==============
@app.route("/helpdesk/new", methods=["GET", "POST"])
@login_required
def helpdesk_new():
    if request.method == "POST":
        username    = (request.form.get("username") or "").strip()
        subject     = (request.form.get("subject") or "").strip()
        description = (request.form.get("description") or "").strip()
        priority    = (request.form.get("priority") or "normal").strip()

        if not username or not subject or not description:
            flash("Lütfen tüm alanları doldurun.", "danger")
            return render_template("helpdesk_new.html")

        if priority not in PRIORITIES:
            priority = "normal"

        try:
            t = HelpDesk(
                username=username, subject=subject, description=description,                         # type: ignore
                priority=priority, created_by=current_user.email                                        # type: ignore                      
            )
            db.session.add(t); db.session.commit()
            flash("Talep başarıyla oluşturuldu.", "success")
            return redirect(url_for("helpdesk_list"))
        except Exception as e:
            db.session.rollback()
            flash(f"Talep oluşturulurken hata oluştu: {e}", "danger")
    return render_template("helpdesk_new.html")

@app.route("/helpdesk")
@login_required
def helpdesk_list():
    q = tickets_q_for_current_user()
    status   = request.args.get("status")
    priority = request.args.get("priority")

    if status in STATUSES:
        q = q.filter_by(status=status)
    if priority in PRIORITIES:
        q = q.filter_by(priority=priority)

    try:
        tickets = q.order_by(HelpDesk.created_at.desc()).all()
    except Exception:
        tickets = q.order_by(HelpDesk.id.desc()).all()
    return render_template("helpdesk_list.html", tickets=tickets)

@app.route("/helpdesk/history")
@login_required
def helpdesk_history():
    q = HelpDeskArchive.query if is_admin() else HelpDeskArchive.query.filter(
        HelpDeskArchive.created_by == current_user.email
    )
    records = q.order_by(HelpDeskArchive.deleted_at.desc()).all()
    return render_template("helpdesk_history.html", records=records)

@app.route("/helpdesk/<int:ticket_id>/status/<string:to>")
@login_required
@admin_required
def helpdesk_update_status(ticket_id: int, to: str):
    if to not in STATUSES:
        flash("Geçersiz durum.", "danger"); return redirect(url_for("helpdesk_list"))
    try:
        t = HelpDesk.query.get_or_404(ticket_id)
        old = t.status
        t.status = to
        t.updated_at = datetime.utcnow()
        t.pending_delete_at = (datetime.utcnow() + timedelta(hours=3)) if to == "kapalı" else None
        db.session.commit()
        flash(f"#{ticket_id} durumu '{to}' olarak güncellendi.", "success")

        if t.created_by:
            warning = ("\n\nUyarı: Bu ticket 3 saat içinde SİLİNECEKTİR.\n"
                       "Açık kalmasını istiyorsanız 3 saat içinde güncelleyin.\n") if to == "kapalı" else ""
            body = (f"Merhaba,\n\n#{t.id} numaralı talebiniz güncellendi.\n"
                    f"Konu      : {t.subject}\nÖnceki    : {old}\nYeni      : {to}\n"
                    f"Güncelleme: {datetime.utcnow():%Y-%m-%d %H:%M UTC}\n{warning}\nSistem: SAP & Help Desk")
            send_mail(t.created_by, f"[Help Desk] #{t.id} durum güncellendi: {to}", body)
    except Exception as e:
        db.session.rollback()
        flash(f"Durum güncellenirken hata oluştu: {e}", "danger")
    return redirect(url_for("helpdesk_list"))

@app.route("/helpdesk/<int:ticket_id>/priority/<string:to>")
@login_required
@admin_required
def helpdesk_update_priority(ticket_id: int, to: str):
    if to not in PRIORITIES:
        flash("Geçersiz öncelik.", "danger"); return redirect(url_for("helpdesk_list"))
    try:
        t = HelpDesk.query.get_or_404(ticket_id)
        t.priority = to
        t.updated_at = datetime.utcnow()
        db.session.commit()
        flash(f"#{ticket_id} öncelik '{to}' olarak güncellendi.", "success")
    except Exception as e:
        db.session.rollback()
        flash(f"Öncelik güncellenirken hata oluştu: {e}", "danger")
    return redirect(url_for("helpdesk_list"))

@app.route("/helpdesk/<int:ticket_id>/edit", methods=["GET", "POST"])
@login_required
def helpdesk_edit(ticket_id: int):
    t = HelpDesk.query.get_or_404(ticket_id)
    # Yetki kontrolü
    if not is_admin() and t.created_by != current_user.email:
        abort(403, description="Bu kaydı güncelleme yetkiniz yok.")

    if request.method == "POST":
        subject     = (request.form.get("subject") or "").strip()
        description = (request.form.get("description") or "").strip()
        priority    = (request.form.get("priority") or "normal").strip()
        if not subject or not description:
            flash("Konu ve açıklama zorunlu.", "danger")
            return render_template("helpdesk_edit.html", t=t)
        if priority not in PRIORITIES:
            priority = "normal"
        try:
            t.subject = subject
            t.description = description
            t.priority = priority
            t.updated_at = datetime.utcnow()
            # Kapalıyken bekleyen silme varsa güncelleme ile iptal
            if t.pending_delete_at is not None:
                t.pending_delete_at = None
            db.session.commit()
            flash("Kayıt güncellendi. (Varsa silme zamanlayıcısı iptal edildi.)", "success")
            return redirect(url_for("helpdesk_list"))
        except Exception as e:
            db.session.rollback()
            flash(f"Güncelleme hatası: {e}", "danger")
    return render_template("helpdesk_edit.html", t=t)

# ============== Grafikler ==============
@app.route("/charts/helpdesk/status.png")
@login_required
@admin_required  # ← Artık yalnızca admin doğrudan URL ile de erişebilir
def chart_helpdesk_status():
    q = tickets_q_for_current_user()
    counts = {
        "açık":        q.filter_by(status="açık").count(),
        "işlem sürecinde": q.filter_by(status="işlem sürecinde").count(),
        "kapalı":      q.filter_by(status="kapalı").count(),
    }
    labels = ["açık", "işlem sürecinde", "kapalı"]
    values = [counts[l] for l in labels]
    fig, ax = plt.subplots(figsize=(5, 3))
    ax.bar(labels, values)
    ax.set_title("Help Desk Durum Dağılımı")
    ax.set_ylabel("Adet")
    ax.grid(axis="y", linestyle="--", alpha=0.4)
    ax.set_yticks(np.arange(0, (max(values) if values else 0) + 2, 1))
    return send_file(_fig_to_png_bytes(fig), mimetype="image/png")

@app.route("/charts/sap/stok_pie.png")
@login_required
def chart_sap_stok_pie():
    ensure_data_folder()
    df = pd.read_csv(BASE_DIR / "data" / "stoklar.csv")
    if "miktar" not in df.columns:
        fig, ax = plt.subplots(figsize=(5, 3))
        ax.text(0.5, 0.5, "miktar kolonu bulunamadı", ha="center", va="center")
        return send_file(_fig_to_png_bytes(fig), mimetype="image/png")

    df["miktar"] = pd.to_numeric(df["miktar"], errors="coerce").fillna(0)
    df = df.sort_values("miktar", ascending=False)
    top5 = df.head(5).copy()
    others_sum = df["miktar"].iloc[5:].sum()

    labels = (top5["malzeme_adi"] if "malzeme_adi" in top5.columns else top5.get("malzeme_kodu")).astype(str).tolist()                          # type: ignore
    values = top5["miktar"].tolist()
    if others_sum > 0:
        labels.append("Diğer"); values.append(others_sum)

    fig, ax = plt.subplots(figsize=(5, 3))
    ax.pie(values, labels=labels, autopct="%1.0f%%", startangle=90)
    ax.set_title("Stok Miktarı (Top 5 + Diğer)")
    return send_file(_fig_to_png_bytes(fig), mimetype="image/png")

@app.route("/charts/sap/siparis_trend.png")
@login_required
def chart_siparis_trend():
    ensure_data_folder()
    df = pd.read_csv(BASE_DIR / "data" / "siparisler.csv")
    if "tarih" in df.columns: df["tarih"] = pd.to_datetime(df["tarih"], errors="coerce")
    if "tutar" in df.columns: df["tutar"] = pd.to_numeric(df["tutar"], errors="coerce").fillna(0)

    grp = (
        df.dropna(subset=["tarih"])
          .groupby(df["tarih"].dt.date)["tutar"]
          .sum().reset_index().sort_values("tarih")
    )
    fig, ax = plt.subplots(figsize=(6, 3))
    ax.plot(grp["tarih"], grp["tutar"], marker="o")
    ax.set_title("Günlük Toplam Sipariş Tutarı")
    ax.set_xlabel("Tarih"); ax.set_ylabel("Tutar")
    ax.grid(True, linestyle="--", alpha=0.4)
    fig.autofmt_xdate()
    return send_file(_fig_to_png_bytes(fig), mimetype="image/png")

# ============== Error Handlers ==============
@app.errorhandler(404)
def not_found(error):
    return render_template("error.html", error_code=404, error_message="Sayfa bulunamadı"), 404

@app.errorhandler(403)
def forbidden(error):
    return render_template("error.html", error_code=403, error_message="Bu işlem için yetkiniz yok"), 403

@app.errorhandler(500)
def server_error(error):
    return render_template("error.html", error_code=500, error_message="Sunucu hatası oluştu"), 500

# ============== CLI ==============
@app.cli.command("db-init")
@with_appcontext
def cli_db_init():
    """Eksik tabloları oluşturur ve örnek verileri ekler."""
    db.create_all()
    ensure_data_folder()
    click.echo("Veritabanı hazır (eksik tablolar oluşturuldu).")
    click.echo("Örnek CSV dosyaları data/ klasöründe oluşturuldu.")

@app.cli.command("create-admin")
@with_appcontext
@click.option("--email", prompt=True)
@click.option("--password", prompt=True, hide_input=True, confirmation_prompt=True)
def create_admin(email, password):
    """Admin kullanıcı oluşturur."""
    db.create_all()
    email = email.strip().lower()
    if User.query.filter_by(email=email).first():
        click.echo("Bu e-posta zaten kayıtlı."); return
    u = User(email=email, role="admin"); u.set_password(password)                                                     # type: ignore                                        
    db.session.add(u); db.session.commit()
    click.echo(f"Admin oluşturuldu: {email}")

@app.cli.command("create-user")
@with_appcontext
@click.option("--email", prompt=True)
@click.option("--password", prompt=True, hide_input=True, confirmation_prompt=True)
def create_user(email, password):
    """Normal kullanıcı oluşturur."""
    db.create_all()
    email = email.strip().lower()
    if User.query.filter_by(email=email).first():
        click.echo("Bu e-posta zaten kayıtlı."); return
    u = User(email=email, role="user"); u.set_password(password)                                                        # type: ignore
    db.session.add(u); db.session.commit()
    click.echo(f"Kullanıcı oluşturuldu: {email}")

@app.cli.command("list-users")
@with_appcontext
def list_users():
    """Tüm kullanıcıları listeler."""
    users = User.query.all()
    if not users:
        click.echo("Hiç kullanıcı bulunamadı."); return
    click.echo("\n📋 Kullanıcı Listesi:\n" + "-"*50)
    for user in users:
        icon = "👑" if user.role == "admin" else "👤"
        click.echo(f"{icon} {user.email} ({user.role})")
    click.echo("-"*50)

@app.cli.command("seed-inventory")
@with_appcontext
def seed_inventory():
    """Demo için 30 cihazlık örnek envanter üretir."""
    import random
    hosts = [f"PC-{i:03d}" for i in range(101, 131)]
    users = ["ali", "ayse", "mehmet", "zeynep", "can", "elif", "murat", "ahmet","kerem","selin","deniz","emre","oğuz"]
    oss = ["Windows 11", "Windows 10", "Ubuntu 22.04", "Ubuntu 20.04", "macOS 12"]
    cpus = ["i5-11400", "i7-9750H", "Ryzen 5 5600U", "M1", "i3-10100"]
    locs = ["İstanbul", "Ankara", "İzmir"]
    statuses = ["active", "repair", "retired"]

    for h in hosts:
        asset = InventoryAsset(
            hostname=h,                                                                                         # type: ignore
            assigned_to=f"{random.choice(users)}@firma.com",                                            # type: ignore                                  
            os=random.choice(oss),                                                                                                              # type: ignore
            cpu=random.choice(cpus),                                                                                                         # type: ignore                         
            ram_gb=random.choice([8, 16, 32]),                                                                              # type: ignore  
            disk_gb=random.choice([256, 512, 1024]),                                                                             # type: ignore                                 
            ip=f"10.0.{random.randint(0,10)}.{random.randint(2,250)}",                                                    # type: ignore
            mac=":".join([f"{random.randint(0,255):02x}" for _ in range(6)]),                                           # type: ignore
            location=random.choice(locs),                                                                               # type: ignore
            status=random.choices(statuses, weights=[0.8, 0.1, 0.1])[0],                                          # type: ignore
            last_seen=datetime.utcnow()                                                      # type: ignore
        )
        db.session.add(asset)
    db.session.commit()
    click.echo("✅ Envanter seed tamam.")

# ============== Main ==============
if __name__ == "__main__":
    with app.app_context():
        db.create_all()
        ensure_data_folder()
    app.run(debug=True)
