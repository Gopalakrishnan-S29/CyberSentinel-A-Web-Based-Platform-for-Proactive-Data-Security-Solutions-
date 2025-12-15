# app.py
import os
import socket
import smtplib
import time
import tempfile
from datetime import datetime
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText


from flask import Flask, render_template, request, redirect, url_for, flash
from flask_apscheduler import APScheduler
from werkzeug.utils import secure_filename

# tools
from tools.portguardian import get_listening_ports, RISKY_PORTS
from tools.tracenet import TraceNet
from tools.metaspy import MetaSpyScanner
from tools.bannerhunter import BannerHunter
from tools.crawleye import CrawlEye

# ===== Flask app setup =====
app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "supersecret")  # override in env for production

# ==== EMAIL CONFIG (use environment variables in production) ====
SMTP_SERVER = os.environ.get("SMTP_SERVER", "smtp.gmail.com")
SMTP_PORT = int(os.environ.get("SMTP_PORT", 587))
SENDER_EMAIL = os.environ.get("SENDER_EMAIL", "")
SENDER_PASSWORD = os.environ.get("SENDER_PASSWORD", "")  # set in env
RECEIVER_EMAIL = os.environ.get("RECEIVER_EMAIL", "")
# =================================================================

# Uploads
ALLOWED_UPLOAD_EXT = {".jpg", ".jpeg", ".png", ".tif", ".tiff", ".pdf", ".docx"}
UPLOAD_DIR = os.environ.get("UPLOAD_DIR", tempfile.gettempdir())
os.makedirs(UPLOAD_DIR, exist_ok=True)


# ---------------- Home / Index ----------------
@app.route("/")
def index():
    return render_template("index.html")


# ---------------- PortGuardian ----------------
@app.route("/portguardian")
def portguardian():
    ports = get_listening_ports()
    return render_template("portguardian.html", ports=ports, risky_ports=RISKY_PORTS)


@app.route("/send_port_report", methods=["POST"])
def send_port_report():
    ports = get_listening_ports()
    risky = [p for p in ports if p.get("risk")]

    if not risky:
        flash("✅ No risky ports detected. No email sent.")
        return redirect(url_for("portguardian"))

    message_body = "⚠️ Risky Ports Report (PortGuardian++)\n\n"
    for p in risky:
        message_body += f"Port: {p.get('port')} | Service: {p.get('service')} | Process: {p.get('process')} (PID: {p.get('pid')})\n"

    msg = MIMEText(message_body)
    msg["Subject"] = "Manual Risky Ports Report - PortGuardian++"
    msg["From"] = SENDER_EMAIL
    msg["To"] = RECEIVER_EMAIL

    try:
        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
            server.starttls()
            if SENDER_PASSWORD:
                server.login(SENDER_EMAIL, SENDER_PASSWORD)
            server.sendmail(SENDER_EMAIL, RECEIVER_EMAIL, msg.as_string())
        flash("📧 Manual report sent successfully!")
    except Exception as e:
        flash(f"❌ Failed to send manual email: {e}")

    return redirect(url_for("portguardian"))


# ---------------- TraceNet ----------------
@app.route("/tracenet", methods=["GET", "POST"])
def tracenet():
    if request.method == "POST":
        target = request.form.get("target", "").strip()
        if not target:
            flash("⚠️ Please enter a target (username or email).", "warning")
            return redirect(url_for("tracenet"))

        tracer = TraceNet(target)
        try:
            result = tracer.run_recon()
        except Exception as e:
            flash(f"❌ TraceNet recon failed: {e}", "danger")
            result = None

        return render_template("tracenet.html", target=target, result=result)

    return render_template("tracenet.html", target=None, result=None)


@app.route("/tracenet/report", methods=["POST"])
def send_tracenet_report():
    target = request.form.get("target", "").strip()
    typ = request.form.get("type", None)

    if not target:
        flash("⚠️ No target supplied for report.", "warning")
        return redirect(url_for("tracenet"))

    tracer = TraceNet(target)
    result = tracer.run_recon()

    html = f"<h2>TraceNet Report for {target}</h2>"
    if result.get("type") == "username":
        html += "<p>Username scan results:</p><ul>"
        for r in result.get("results", []):
            status = "Found" if r.get("found") else "Not Found"
            html += f"<li>{r.get('platform')}: {status} (HTTP: {r.get('http_status')}) - <a href='{r.get('url')}'>{r.get('url')}</a></li>"
        html += "</ul>"
        subject = f"TraceNet Username Report - {target}"
    else:
        html += "<p>Email breach scan:</p>"
        if result.get("status") == "no_api":
            html += "<p>HIBP API key not configured; no breach information available.</p>"
        elif result.get("status") == "error":
            html += "<p>Error while checking breaches.</p>"
        elif result.get("status") == "ok" and result.get("breaches"):
            html += "<ul>"
            for b in result.get("breaches"):
                html += f"<li><strong>{b.get('Name')}</strong> — {b.get('BreachDate')} — {', '.join(b.get('DataClasses', []))}</li>"
            html += "</ul>"
        else:
            html += "<p>No breaches found.</p>"
        subject = f"TraceNet Email Breach Report - {target}"

    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"] = SENDER_EMAIL
    msg["To"] = RECEIVER_EMAIL
    msg.attach(MIMEText(html, "html"))

    try:
        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
            server.starttls()
            if SENDER_PASSWORD:
                server.login(SENDER_EMAIL, SENDER_PASSWORD)
            server.sendmail(SENDER_EMAIL, RECEIVER_EMAIL, msg.as_string())
        flash("📧 TraceNet report sent successfully!")
    except Exception as e:
        flash(f"❌ Failed to send TraceNet report: {e}")

    return redirect(url_for("tracenet"))


# ---------------- MetaSpy (file metadata) ----------------
@app.route("/metaspy", methods=["GET", "POST"])
def metaspy():
    if request.method == "POST":
        uploaded = request.files.get("file")
        if not uploaded:
            flash("⚠️ Please select a file to upload.", "warning")
            return redirect(url_for("metaspy"))

        filename = secure_filename(uploaded.filename)
        ext = os.path.splitext(filename)[1].lower()
        if ext not in ALLOWED_UPLOAD_EXT:
            flash("⚠️ Unsupported file type.", "warning")
            return redirect(url_for("metaspy"))

        save_path = os.path.join(UPLOAD_DIR, f"metaspy_{int(time.time())}_{filename}")
        uploaded.save(save_path)

        scanner = MetaSpyScanner()
        try:
            result = scanner.analyze_file(save_path)
        except Exception as e:
            flash(f"❌ MetaSpy failed: {e}", "danger")
            result = {"error": str(e)}

        return render_template("metaspy.html", target=filename, result=result)

    return render_template("metaspy.html", target=None, result=None)


# ---------------- BannerHunter ----------------
@app.route("/bannerhunter", methods=["GET", "POST"])
def bannerhunter():
    if request.method == "POST":
        target = request.form.get("target", "").strip()
        ports_raw = request.form.get("ports", "").strip()
        if not target:
            flash("⚠️ Please enter a target (hostname or IP).", "warning")
            return redirect(url_for("bannerhunter"))

        ports = None
        if ports_raw:
            try:
                ports = [int(p.strip()) for p in ports_raw.split(",") if p.strip()]
            except Exception:
                ports = None

        hunter = BannerHunter(target, ports=ports)
        try:
            result = hunter.scan()
        except Exception as e:
            flash(f"❌ BannerHunter scan failed: {e}", "danger")
            result = None

        return render_template("bannerhunter.html", target=target, result=result, ports=ports_raw)

    return render_template("bannerhunter.html", target=None, result=None, ports=None)


# ---------------- Scheduled Email (PortGuardian) ----------------
def generate_risky_report():
    ports = get_listening_ports()
    risky_ports = [p for p in ports if p.get("risk")]

    if not risky_ports:
        return "<p>No risky ports were open in the last scan ✅</p>"

    html = """
    <h2>PortGuardian++ - Daily Risky Ports Report 🔒</h2>
    <p>Here are the risky ports detected:</p>
    <table border="1" cellpadding="5" cellspacing="0">
        <tr>
            <th>Port</th>
            <th>Service</th>
            <th>Process</th>
            <th>PID</th>
        </tr>
    """
    for p in risky_ports:
        html += f"""
        <tr>
            <td>{p.get('port')}</td>
            <td>{p.get('service')}</td>
            <td>{p.get('process')}</td>
            <td>{p.get('pid')}</td>
        </tr>
        """
    html += "</table>"
    return html


def send_email_report():
    report_html = generate_risky_report()

    msg = MIMEMultipart("alternative")
    msg["Subject"] = "PortGuardian++ - Daily Risky Ports Report"
    msg["From"] = SENDER_EMAIL
    msg["To"] = RECEIVER_EMAIL

    msg.attach(MIMEText(report_html, "html"))

    try:
        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
            server.starttls()
            if SENDER_PASSWORD:
                server.login(SENDER_EMAIL, SENDER_PASSWORD)
            server.sendmail(SENDER_EMAIL, RECEIVER_EMAIL, msg.as_string())
        print("✅ Daily Email report sent successfully!")
    except Exception as e:
        print("❌ Email sending failed:", e)


# ===== Scheduler =====
class Config:
    SCHEDULER_API_ENABLED = True


app.config.from_object(Config)
scheduler = APScheduler()
scheduler.init_app(app)
scheduler.start()


@scheduler.task("cron", id="daily_email_job", hour=0, minute=0)
def scheduled_task():
    print("⏰ Running scheduled risky port report...")
    send_email_report()


# ---------------- Static pages ----------------
@app.route("/phisheye")
def phisheye():
    return render_template("phisheye.html")


@app.route("/wifiguard")
def wifiguard():
    return render_template("wifiguard.html")


@app.route("/logsentinel")
def logsentinel():
    return render_template("logsentinel.html")


@app.route("/stegguardian")
def stegguardian():
    return render_template("stegguardian.html")


@app.route("/leakscope")
def leakscope():
    return render_template("leakscope.html")


@app.route("/crawleye", methods=["GET", "POST"])
def crawleye():
    if request.method == "POST":
        target = request.form.get("target", "").strip()
        depth = int(request.form.get("depth", 50))

        crawler = CrawlEye(target, max_pages=depth)
        try:
            result = crawler.crawl()
        except Exception as e:
            flash(f"❌ CrawlEye failed: {e}", "danger")
            result = None

        return render_template("crawleye.html", result=result)

    return render_template("crawleye.html", result=None)


# ---- Run the app ----
if __name__ == "__main__":
    host = os.environ.get("FLASK_HOST", "127.0.0.1")
    port = int(os.environ.get("FLASK_PORT", 8080))
    debug = os.environ.get("FLASK_DEBUG", "1") == "1"
    app.run(debug=debug, host=host, port=port)
