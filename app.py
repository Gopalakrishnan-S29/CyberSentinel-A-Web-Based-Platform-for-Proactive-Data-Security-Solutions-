from flask import Flask, render_template, request, redirect, url_for, flash
import os
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from flask_apscheduler import APScheduler



# ===== Ensure tools package importable =====
from tools.portguardian import get_listening_ports, RISKY_PORTS
from tools.tracenet import TraceNet

app = Flask(__name__)
app.secret_key = "supersecret"  # Needed for flash messages


# ==== EMAIL CONFIG (Update These) ====
SMTP_SERVER = "smtp.gmail.com"
SMTP_PORT = 587
SENDER_EMAIL = "useforhack0629@gmail.com"
SENDER_PASSWORD = "pyascscuhmnhqcsx"  # Use Gmail App Password
RECEIVER_EMAIL = "bharathkumarnatarajan6@gmail.com"
# =====================================


# ---- Home page ----
@app.route("/")
def index():
    return render_template("index.html")


@app.route("/portguardian")
def portguardian():
    ports = get_listening_ports()
    return render_template("portguardian.html", ports=ports, risky_ports=RISKY_PORTS)


# ✅ Route to send email report manually
@app.route("/send_port_report", methods=["POST"])
def send_port_report():
    ports = get_listening_ports()
    risky = [p for p in ports if p["risk"]]

    if not risky:
        flash("✅ No risky ports detected. No email sent.")
        return redirect(url_for("portguardian"))

    # Build plain text message body
    message_body = "⚠️ Risky Ports Report (PortGuardian++)\n\n"
    for p in risky:
        message_body += f"Port: {p['port']} | Service: {p['service']} | Process: {p['process']} (PID: {p['pid']})\n"

    msg = MIMEText(message_body)
    msg["Subject"] = "Manual Risky Ports Report - PortGuardian++"
    msg["From"] = SENDER_EMAIL
    msg["To"] = RECEIVER_EMAIL

    try:
        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
            server.starttls()
            server.login(SENDER_EMAIL, SENDER_PASSWORD)
            server.sendmail(SENDER_EMAIL, RECEIVER_EMAIL, msg.as_string())
        flash("📧 Manual report sent successfully!")
    except Exception as e:
        flash(f"❌ Failed to send manual email: {e}")

    return redirect(url_for("portguardian"))

# -------- TraceNet Recon Module (new) --------
@app.route("/tracenet", methods=["GET", "POST"])
def tracenet():
    """
    GET: show form
    POST: run TraceNet.run_recon() and render results
    """
    if request.method == "POST":
        target = request.form.get("target", "").strip()
        if not target:
            flash("⚠️ Please enter a target (hostname or IP).", "warning")
            return redirect(url_for("tracenet"))

        tracer = TraceNet(target)
        result = tracer.run_recon()
        return render_template("tracenet.html", target=target, result=result)

    # GET
    return render_template("tracenet.html", target=None, result=None)

# ==== Scheduled Email Functions ====
def generate_risky_report():
    """Generate HTML report of risky ports."""
    ports = get_listening_ports()
    risky_ports = [p for p in ports if p["risk"]]

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
            <td>{p['port']}</td>
            <td>{p['service']}</td>
            <td>{p['process']}</td>
            <td>{p['pid']}</td>
        </tr>
        """
    html += "</table>"
    return html


def send_email_report():
    """Send risky port report via email (HTML version)."""
    report_html = generate_risky_report()

    msg = MIMEMultipart("alternative")
    msg["Subject"] = "PortGuardian++ - Daily Risky Ports Report"
    msg["From"] = SENDER_EMAIL
    msg["To"] = RECEIVER_EMAIL

    msg.attach(MIMEText(report_html, "html"))

    try:
        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
            server.starttls()
            server.login(SENDER_EMAIL, SENDER_PASSWORD)
            server.sendmail(SENDER_EMAIL, RECEIVER_EMAIL, msg.as_string())
        print("✅ Daily Email report sent successfully!")
    except Exception as e:
        print("❌ Email sending failed:", e)


# ========= APScheduler =========
class Config:
    SCHEDULER_API_ENABLED = True

app.config.from_object(Config)
scheduler = APScheduler()
scheduler.init_app(app)
scheduler.start()

# Run email job every day at midnight
@scheduler.task("cron", id="daily_email_job", hour=0, minute=0)
def scheduled_task():
    print("⏰ Running scheduled risky port report...")
    send_email_report()
# ===============================


# ---- Other tool pages (Static Templates) ----
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

@app.route("/metaspy")
def metaspy():
    return render_template("metaspy.html")

@app.route("/bannerhunter")
def bannerhunter():
    return render_template("bannerhunter.html")

@app.route("/leakscope")
def leakscope():
    return render_template("leakscope.html")

@app.route("/crawleye")
def crawleye():
    return render_template("crawleye.html")


# ---- Run the app ----
if __name__ == "__main__":
    host = os.environ.get("FLASK_HOST", "127.0.0.1")
    port = int(os.environ.get("FLASK_PORT", 5000))
    debug = os.environ.get("FLASK_DEBUG", "1") == "1"
    app.run(debug=debug, host=host, port=port)
