"""
badge.py - Dynamic SVG Badge and Embeddable Verification Seal Generator for CertValid.
Generates lightweight, scalable vector SVG badges for GitHub READMEs, personal portfolios,
resumes, and institutional websites.
"""

import html


def generate_svg_badge(cert: dict, style: str = 'shield', theme: str = 'dark') -> str:
    """
    Generate dynamic vector SVG badge markup for a given certificate.
    Supported styles:
      - 'shield': Dual-tone Shields.io / GitHub README style badge.
      - 'pill': Rounded compact pill badge.
      - 'card': Detailed credential mini-card badge (360x115).
    """
    if not cert:
        cert = {}
        status = 'not_found'
    else:
        if cert.get('status') == 'revoked':
            status = 'revoked'
        elif cert.get('is_expired') or cert.get('effective_status') == 'expired':
            status = 'expired'
        else:
            status = 'active'

    status_configs = {
        'active': {
            'text': 'Verified Authentic',
            'color': '#10b981',
            'border': '#059669',
            'symbol': '✓',
            'label': 'VERIFIED'
        },
        'revoked': {
            'text': 'Revoked Credential',
            'color': '#ef4444',
            'border': '#dc2626',
            'symbol': '✗',
            'label': 'REVOKED'
        },
        'expired': {
            'text': 'Expired Credential',
            'color': '#f59e0b',
            'border': '#d97706',
            'symbol': '⏳',
            'label': 'EXPIRED'
        },
        'not_found': {
            'text': 'Not Found',
            'color': '#64748b',
            'border': '#475569',
            'symbol': '?',
            'label': 'UNKNOWN'
        }
    }

    cfg = status_configs.get(status, status_configs['not_found'])

    student_name = html.escape(str(cert.get('student_name', 'Recipient Name')))
    cert_id = html.escape(str(cert.get('cert_id', '')))
    course_name = html.escape(str(cert.get('course_name', 'Course Name')))
    issuer_name = html.escape(str(cert.get('issuer_name', 'CertValid Registry')))

    if style == 'pill':
        return _generate_pill_badge(cert, cfg, theme)
    elif style == 'card':
        return _generate_card_badge(cert, cfg, theme, student_name, cert_id, course_name, issuer_name)
    else:
        return _generate_shield_badge(cert, cfg, theme)


def _generate_shield_badge(cert: dict, cfg: dict, theme: str) -> str:
    """Generate dual-tone Shields.io style badge."""
    left_text = "CertValid"
    right_text = f"{cfg['symbol']} {cfg['text']}"

    left_len = len(left_text) * 7.0 + 20
    right_len = len(right_text) * 7.0 + 16
    total_width = int(left_len + right_len)
    height = 22

    left_mid = int(left_len / 2)
    right_mid = int(left_len + right_len / 2)

    bg_left = '#18181b' if theme == 'dark' else '#334155'
    bg_right = cfg['color']

    return f'''<svg xmlns="http://www.w3.org/2000/svg" width="{total_width}" height="{height}" role="img" aria-label="{left_text}: {right_text}">
  <title>{left_text}: {right_text}</title>
  <linearGradient id="s" x2="0" y2="100%">
    <stop offset="0" stop-color="#fff" stop-opacity=".15"/>
    <stop offset="1" stop-opacity=".1"/>
  </linearGradient>
  <clipPath id="r">
    <rect width="{total_width}" height="{height}" rx="4" fill="#fff"/>
  </clipPath>
  <g clip-path="url(#r)">
    <rect width="{int(left_len)}" height="{height}" fill="{bg_left}"/>
    <rect x="{int(left_len)}" width="{int(right_len)}" height="{height}" fill="{bg_right}"/>
    <rect width="{total_width}" height="{height}" fill="url(#s)"/>
  </g>
  <g fill="#fff" text-anchor="middle" font-family="Verdana,Geneva,DejaVu Sans,sans-serif" text-rendering="geometricPrecision" font-size="11">
    <text aria-hidden="true" x="{left_mid}" y="16" fill="#000" fill-opacity=".3">{left_text}</text>
    <text x="{left_mid}" y="15">{left_text}</text>
    <text aria-hidden="true" x="{right_mid}" y="16" fill="#000" fill-opacity=".3">{right_text}</text>
    <text x="{right_mid}" y="15" font-weight="bold">{right_text}</text>
  </g>
</svg>'''


def _generate_pill_badge(cert: dict, cfg: dict, theme: str) -> str:
    """Generate modern rounded pill badge."""
    cert_id = cert.get('cert_id', '')
    cert_id_display = f" • {cert_id}" if cert_id else ""
    text = f"🛡️ CertValid {cfg['symbol']} {cfg['text']}{cert_id_display}"
    width = int(len(text) * 7.5 + 26)
    height = 28

    bg_color = "#090d16" if theme == 'dark' else "#ffffff"
    text_color = "#f1f5f9" if theme == 'dark' else "#0f172a"
    border_color = cfg['color']

    calc_pos = int(len(f"CertValid {cfg['symbol']} {cfg['text']}") * 7.2 + 32)

    return f'''<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" role="img" aria-label="{text}">
  <title>{text}</title>
  <rect width="{width}" height="{height}" rx="14" fill="{bg_color}" stroke="{border_color}" stroke-width="1.5"/>
  <circle cx="16" cy="14" r="4.5" fill="{cfg['color']}"/>
  <g fill="{text_color}" font-family="system-ui,-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,sans-serif" font-size="11.5" text-rendering="geometricPrecision">
    <text x="28" y="18" font-weight="bold">CertValid</text>
    <text x="86" y="18" fill="{cfg['color']}" font-weight="600">{cfg['symbol']} {cfg['text']}</text>
    <text x="{calc_pos}" y="18" fill="#94a3b8" font-size="10.5">{cert_id_display}</text>
  </g>
</svg>'''


def _generate_card_badge(cert: dict, cfg: dict, theme: str, student_name: str, cert_id: str, course_name: str, issuer_name: str) -> str:
    """Generate detailed credential mini-card vector badge (360x115)."""
    width = 360
    height = 115

    bg_fill = "#0d111a" if theme == 'dark' else "#ffffff"
    text_main = "#f8fafc" if theme == 'dark' else "#0f172a"
    text_sub = "#94a3b8" if theme == 'dark' else "#475569"
    border_color = cfg['color']

    return f'''<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" viewBox="0 0 {width} {height}" role="img" aria-label="CertValid Credential: {student_name}">
  <title>CertValid Credential: {student_name} - {course_name}</title>
  <defs>
    <linearGradient id="bgGrad" x1="0%" y1="0%" x2="100%" y2="100%">
      <stop offset="0%" stop-color="{bg_fill}"/>
      <stop offset="100%" stop-color="#161e2e"/>
    </linearGradient>
    <linearGradient id="accentGrad" x1="0%" y1="0%" x2="100%" y2="0%">
      <stop offset="0%" stop-color="{cfg['color']}"/>
      <stop offset="100%" stop-color="#38bdf8"/>
    </linearGradient>
  </defs>

  <rect x="1" y="1" width="{width-2}" height="{height-2}" rx="8" fill="url(#bgGrad)" stroke="{border_color}" stroke-width="1.2"/>
  <rect x="1" y="1" width="5" height="{height-2}" rx="2" fill="url(#accentGrad)"/>

  <g transform="translate(18, 22)">
    <circle cx="16" cy="16" r="16" fill="{cfg['color']}" fill-opacity="0.15"/>
    <path d="M16 6 L26 10.5 V18 C26 23.5 21.5 28 16 30 C10.5 28 6 23.5 6 18 V10.5 Z" fill="none" stroke="{cfg['color']}" stroke-width="2"/>
    <path d="M12 18 L15 21 L21 14" fill="none" stroke="{cfg['color']}" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>
  </g>

  <g font-family="system-ui,-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,sans-serif" text-rendering="geometricPrecision">
    <text x="60" y="28" font-size="10" font-weight="700" fill="#38bdf8" letter-spacing="0.8">CERTVALID VERIFIED CREDENTIAL</text>
    <text x="60" y="48" font-size="14" font-weight="700" fill="{text_main}">{student_name[:32]}</text>
    <text x="60" y="66" font-size="11.5" fill="{text_sub}">{course_name[:36]}</text>
    <text x="60" y="82" font-size="10" fill="{text_sub}">Issued by: <tspan fill="{text_main}">{issuer_name[:28]}</tspan></text>

    <g transform="translate({width - 105}, 16)">
      <rect width="90" height="20" rx="10" fill="{cfg['color']}" fill-opacity="0.2" stroke="{cfg['color']}" stroke-width="1"/>
      <text x="45" y="14" font-size="9.5" font-weight="700" fill="{cfg['color']}" text-anchor="middle">{cfg['symbol']} {cfg['label']}</text>
    </g>

    <line x1="60" y1="92" x2="{width - 18}" y2="92" stroke="#334155" stroke-width="0.7"/>
    <text x="60" y="104" font-size="9" font-family="monospace" fill="#64748b">ID: {cert_id}</text>
    <text x="{width - 18}" y="104" font-size="8.5" fill="#64748b" text-anchor="end">certvalid.io/verify</text>
  </g>
</svg>'''
