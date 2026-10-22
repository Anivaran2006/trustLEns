"""
Generate realistic forensic demonstration artifacts for TrustLens AI Multi-Modal evaluation.
Produces Quishing (QR code scam) and Fake Amazon Invoice images.
"""

import os
import qrcode
from PIL import Image, ImageDraw, ImageFont

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SAMPLES_DIR = os.path.join(PROJECT_ROOT, "frontend", "samples")
os.makedirs(SAMPLES_DIR, exist_ok=True)

def create_quishing_sample():
    # Generate QR Code pointing to suspicious URL
    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_M,
        box_size=8,
        border=2,
    )
    qr.add_data("http://toll-violation-pay.xyz/notice?id=99281")
    qr.make(fit=True)
    qr_img = qr.make_image(fill_color="black", back_color="white").convert("RGB")

    # Create canvas
    canvas = Image.new("RGB", (650, 750), color="#ffffff")
    draw = ImageDraw.Draw(canvas)

    # Red Warning Banner
    draw.rectangle([(0, 0), (650, 70)], fill="#b91c1c")
    draw.text((30, 22), "STATE DEPARTMENT OF TRANSPORTATION", fill="#ffffff")

    # Title & Notice
    draw.rectangle([(30, 90), (620, 130)], fill="#fee2e2", outline="#ef4444")
    draw.text((45, 102), "FINAL NOTICE OF UNPAID TOLL VIOLATION #TL-88219", fill="#991b1b")

    # Body Text
    body_text = (
        "Vehicle License: 7XYZ891 | Violation Date: 10/18/2026\n\n"
        "Our automated plate readers recorded unpaid highway toll transit.\n"
        "An outstanding fee of $48.50 is immediately delinquent.\n\n"
        "WARNING: Failure to settle balance within 24 hours will result in:\n"
        " • Registration suspension and DMV vehicle hold\n"
        " • Referral to collections with $150.00 additional administrative fine\n\n"
        "SCAN QR CODE BELOW IMMEDIATELY TO SETTLE WITH CARD:"
    )
    draw.text((40, 150), body_text, fill="#1f2937")

    # Paste QR Code
    canvas.paste(qr_img, (220, 390))

    # Footer note
    draw.text((120, 640), "Authorized Digital Payment Portal: toll-violation-pay.xyz", fill="#4b5563")
    draw.text((150, 670), "DO NOT DISREGARD THIS OFFICIAL ENFORCEMENT CITATION", fill="#b91c1c")

    out_path = os.path.join(SAMPLES_DIR, "sample_quishing_scam.png")
    canvas.save(out_path)
    print(f"Created Quishing sample: {out_path}")

def create_fake_invoice_sample():
    canvas = Image.new("RGB", (700, 780), color="#f8fafc")
    draw = ImageDraw.Draw(canvas)

    # Header
    draw.rectangle([(0, 0), (700, 80)], fill="#0f172a")
    draw.text((35, 25), "AMAZON SERVICES LLC — ORDER CONFIRMATION", fill="#38bdf8")

    # Order Details Box
    draw.rectangle([(35, 100), (665, 200)], fill="#ffffff", outline="#cbd5e1")
    draw.text((50, 115), "ORDER ID: #AMZ-992182-4410", fill="#0f172a")
    draw.text((50, 140), "DATE: October 19, 2026", fill="#64748b")
    draw.text((50, 165), "PAYMENT METHOD: Auto-Debited from Card ending in 4921", fill="#64748b")

    # Line Item Box
    draw.rectangle([(35, 220), (665, 340)], fill="#ffffff", outline="#cbd5e1")
    draw.text((50, 235), "ITEM DESCRIPTION", fill="#475569")
    draw.text((550, 235), "AMOUNT", fill="#475569")
    draw.line([(50, 260), (650, 260)], fill="#e2e8f0", width=1)
    draw.text((50, 275), "Geek Squad & Amazon Total Tech Protection (3 Year Auto-Renewal)", fill="#0f172a")
    draw.text((560, 275), "$899.99", fill="#0f172a")

    draw.rectangle([(35, 360), (665, 410)], fill="#f1f5f9")
    draw.text((450, 375), "TOTAL CHARGE:  $899.99 USD", fill="#0f172a")

    # Big Red Extortion Call-to-Action Box (Classic Refund Scam)
    draw.rectangle([(35, 440), (665, 660)], fill="#fef2f2", outline="#dc2626", width=2)
    draw.text((50, 460), "IMPORTANT — DID YOU NOT AUTHORIZE THIS ORDER?", fill="#991b1b")
    call_text = (
        "This subscription has been automatically debited from your checking account.\n\n"
        "If you did NOT authorize this transaction of $899.99, you must call our\n"
        "24/7 Fraud & Cancellation Helpline within 24 hours:\n\n"
        "   TOLL-FREE HELPLINE:  +1-800-555-0199\n\n"
        "Our security representatives will cancel the auto-debit and issue a\n"
        "full immediate refund to your original payment method.\n\n"
        "Do NOT reply to this automated email. Immediate telephone verification required."
    )
    draw.text((50, 490), call_text, fill="#7f1d1d")

    out_path = os.path.join(SAMPLES_DIR, "sample_amazon_fake_invoice.png")
    canvas.save(out_path)
    print(f"Created Fake Invoice sample: {out_path}")

if __name__ == "__main__":
    create_quishing_sample()
    create_fake_invoice_sample()
