"""
social.py - Open Graph Social Cards, Schema.org JSON-LD, and LinkedIn Certification Integration.
Provides dynamic 1200x630 social preview image cards, 1-click LinkedIn Add-to-Profile URLs,
and W3C / Schema.org EducationalOccupationalCredential structured data.
"""

import io
import urllib.parse
from PIL import Image, ImageDraw, ImageFont


def get_linkedin_add_url(cert: dict, verify_url: str) -> str:
    """
    Generate official 1-click 'Add to LinkedIn Profile' certification URL.
    Pre-fills credential name, issuing authority, certificate ID, and verification link.
    """
    if not cert:
        return ""

    issue_date = cert.get('issue_date', '')
    year = ''
    month = ''
    if issue_date and '-' in issue_date:
        parts = issue_date.split('-')
        year = parts[0]
        if len(parts) > 1:
            try:
                month = str(int(parts[1]))
            except ValueError:
                pass

    expires_at = cert.get('expires_at', '')
    exp_year = ''
    exp_month = ''
    if expires_at and '-' in expires_at:
        exp_parts = expires_at.split('-')
        exp_year = exp_parts[0]
        if len(exp_parts) > 1:
            try:
                exp_month = str(int(exp_parts[1]))
            except ValueError:
                pass

    params = {
        'startTask': 'CERTIFICATION_NAME',
        'name': cert.get('course_name', 'Certificate'),
        'organizationName': cert.get('issuer_name', 'CertValid Registry'),
        'certId': cert.get('cert_id', ''),
        'certUrl': verify_url,
    }
    if year:
        params['issueYear'] = year
    if month:
        params['issueMonth'] = month
    if exp_year:
        params['expirationYear'] = exp_year
    if exp_month:
        params['expirationMonth'] = exp_month

    return 'https://www.linkedin.com/profile/add?' + urllib.parse.urlencode(params)


def get_credential_json_ld(cert: dict, verify_url: str, badge_url: str = '') -> dict:
    """
    Generate W3C / Schema.org EducationalOccupationalCredential structured data dictionary.
    Enables rich search engine indexing and verifiable credential metadata.
    """
    if not cert:
        return {}

    status = 'ACTIVE'
    if cert.get('status') == 'revoked':
        status = 'REVOKED'
    elif cert.get('is_expired') or cert.get('effective_status') == 'expired':
        status = 'EXPIRED'

    data = {
        "@context": "https://schema.org",
        "@type": "EducationalOccupationalCredential",
        "name": cert.get('course_name', 'Certificate of Completion'),
        "description": f"Verified Credential awarded to {cert.get('student_name', 'Recipient')} by {cert.get('issuer_name', 'CertValid Authority')}.",
        "credentialCategory": "Certificate of Achievement",
        "identifier": cert.get('cert_id', ''),
        "url": verify_url,
        "validFrom": cert.get('issue_date', ''),
        "recognizedBy": {
            "@type": "EducationalOrganization",
            "name": cert.get('issuer_name', 'CertValid Authority')
        },
        "issuer": {
            "@type": "Organization",
            "name": cert.get('issuer_name', 'CertValid Authority')
        },
        "credentialStatus": status
    }
    if cert.get('expires_at'):
        data["validUntil"] = cert.get('expires_at')
    if badge_url:
        data["image"] = badge_url

    return data


def generate_social_card_png(cert: dict) -> bytes:
    """
    Generate a high-resolution 1200x630 Open Graph / Twitter Card social preview PNG image.
    Features dark glassmorphism theme, official gold seal, recipient name, course, and verification ribbon.
    """
    w, h = 1200, 630
    img = Image.new('RGB', (w, h), color='#090d16')
    draw = ImageDraw.Draw(img)

    status = (cert.get('status') or 'active').lower()
    if cert.get('is_expired') or cert.get('effective_status') == 'expired':
        status = 'expired'

    status_colors = {
        'active': ('#10b981', '#059669', 'VERIFIED AUTHENTIC'),
        'revoked': ('#ef4444', '#dc2626', 'REVOKED CREDENTIAL'),
        'expired': ('#f59e0b', '#d97706', 'EXPIRED CREDENTIAL'),
    }
    color_main, color_border, status_label = status_colors.get(status, ('#10b981', '#059669', 'VERIFIED AUTHENTIC'))

    # Outer decorative borders
    draw.rectangle([20, 20, w - 20, h - 20], outline='#1e293b', width=2)
    draw.rectangle([28, 28, w - 28, h - 28], outline=color_main, width=3)

    # Top accent header stripe
    draw.rectangle([30, 30, w - 30, 42], fill=color_main)

    # Brand Title
    draw.text((60, 70), "CERTVALID ENTERPRISE REGISTRY", fill='#38bdf8')

    # Status Pill
    draw.rounded_rectangle([w - 330, 65, w - 60, 105], radius=20, fill='#1e293b', outline=color_main, width=2)
    draw.text((w - 305, 75), f"● {status_label}", fill=color_main)

    # Recipient Name
    student_name = str(cert.get('student_name', 'Recipient Name'))
    draw.text((60, 165), "THIS IS TO CERTIFY THAT", fill='#94a3b8')
    draw.text((60, 210), student_name[:40], fill='#ffffff')

    # Course
    course_name = str(cert.get('course_name', 'Course / Programme'))
    draw.text((60, 305), "HAS SUCCESSFULLY COMPLETED", fill='#94a3b8')
    draw.text((60, 340), course_name[:48], fill='#38bdf8')

    # Authority & Date
    issuer_name = str(cert.get('issuer_name', 'CertValid Authority'))
    issue_date = str(cert.get('issue_date', ''))
    draw.text((60, 425), f"Issued by: {issuer_name[:45]}   |   Date: {issue_date}", fill='#cbd5e1')

    # Expiry notice if present
    if cert.get('expires_at'):
        exp_text = f"Valid Until: {cert.get('expires_at')}"
        if cert.get('is_expired'):
            exp_text += " [EXPIRED]"
        draw.text((60, 460), exp_text, fill='#f59e0b')

    # Middle Divider
    draw.line([60, 510, w - 60, 510], fill='#1e293b', width=2)

    # Footer Metadata
    cert_id = str(cert.get('cert_id', ''))
    draw.text((60, 540), f"CERTIFICATE ID: {cert_id}", fill='#d4af37')
    draw.text((60, 570), "SECURED WITH ED25519 ASYMMETRIC DIGITAL SIGNATURES", fill='#64748b')
    draw.text((w - 340, 555), "VERIFY: certvalid.io/verify", fill='#38bdf8')

    buf = io.BytesIO()
    img.save(buf, format='PNG')
    return buf.getvalue()
