"""
VulnScan Pro — PBL Presentation Generator
Generates a professional dark-themed PPTX presentation.
"""

from pptx import Presentation
from pptx.util import Inches, Pt, Emu
from pptx.dml.color import RGBColor
from pptx.enum.text import PP_ALIGN
from pptx.util import Inches, Pt
import copy

# ─── COLOUR PALETTE ──────────────────────────────────────────────────────────
BG_DARK      = RGBColor(0x07, 0x07, 0x10)   # Near-black navy
BG_CARD      = RGBColor(0x0F, 0x0F, 0x23)   # Slightly lighter card bg
NEON_GREEN   = RGBColor(0x00, 0xE5, 0x3A)   # Primary accent
NEON_BLUE    = RGBColor(0x38, 0xBD, 0xF8)   # Secondary accent
GOLD         = RGBColor(0xF5, 0xC5, 0x18)   # Highlight / label
RED_ACCENT   = RGBColor(0xEF, 0x44, 0x44)   # Danger / critical
ORANGE       = RGBColor(0xF9, 0x73, 0x16)
WHITE        = RGBColor(0xFF, 0xFF, 0xFF)
OFF_WHITE    = RGBColor(0xD1, 0xD5, 0xDB)
MUTED        = RGBColor(0x6B, 0x72, 0x80)
BORDER       = RGBColor(0x1E, 0x1E, 0x3A)

SLIDE_W = Inches(13.33)
SLIDE_H = Inches(7.5)

# ─── HELPER UTILITIES ─────────────────────────────────────────────────────────

def new_prs():
    prs = Presentation()
    prs.slide_width  = SLIDE_W
    prs.slide_height = SLIDE_H
    return prs

def blank_slide(prs):
    blank_layout = prs.slide_layouts[6]   # completely blank
    return prs.slides.add_slide(blank_layout)

def fill_bg(slide, color=BG_DARK):
    """Paint the slide background a solid colour."""
    background = slide.background
    fill = background.fill
    fill.solid()
    fill.fore_color.rgb = color

def add_rect(slide, l, t, w, h, fill_color, alpha=None, line_color=None, line_width=Pt(0)):
    from pptx.util import Emu
    shape = slide.shapes.add_shape(
        1,   # MSO_SHAPE_TYPE.RECTANGLE
        l, t, w, h
    )
    shape.line.width = line_width
    if line_color:
        shape.line.color.rgb = line_color
    else:
        shape.line.fill.background()
    shape.fill.solid()
    shape.fill.fore_color.rgb = fill_color
    return shape

def add_text(slide, text, l, t, w, h,
             font_size=18, bold=False, color=WHITE,
             align=PP_ALIGN.LEFT, italic=False,
             font_name="Calibri", word_wrap=True):
    txBox = slide.shapes.add_textbox(l, t, w, h)
    tf = txBox.text_frame
    tf.word_wrap = word_wrap
    p = tf.paragraphs[0]
    p.alignment = align
    run = p.add_run()
    run.text = text
    run.font.size  = Pt(font_size)
    run.font.bold  = bold
    run.font.color.rgb = color
    run.font.italic = italic
    run.font.name  = font_name
    return txBox

def add_para(tf, text, font_size=14, bold=False, color=OFF_WHITE,
             align=PP_ALIGN.LEFT, italic=False, space_before=Pt(4), font_name="Calibri"):
    """Add a paragraph to an existing text frame."""
    p = tf.add_paragraph()
    p.alignment = align
    p.space_before = space_before
    run = p.add_run()
    run.text = text
    run.font.size  = Pt(font_size)
    run.font.bold  = bold
    run.font.color.rgb = color
    run.font.italic = italic
    run.font.name  = font_name
    return p

def add_textbox_multiline(slide, lines, l, t, w, h,
                          default_size=13, default_color=OFF_WHITE, font_name="Calibri"):
    """
    lines = list of dicts:
      {"text": str, "size": int, "bold": bool, "color": RGBColor, "italic": bool}
    """
    txBox = slide.shapes.add_textbox(l, t, w, h)
    tf = txBox.text_frame
    tf.word_wrap = True
    first = True
    for line in lines:
        if first:
            p = tf.paragraphs[0]
            first = False
        else:
            p = tf.add_paragraph()
        p.space_before = line.get("space_before", Pt(3))
        p.alignment = line.get("align", PP_ALIGN.LEFT)
        run = p.add_run()
        run.text = line.get("text", "")
        run.font.size  = Pt(line.get("size", default_size))
        run.font.bold  = line.get("bold", False)
        run.font.italic = line.get("italic", False)
        run.font.color.rgb = line.get("color", default_color)
        run.font.name  = font_name
    return txBox

def section_label(slide, label_text, y_offset=Inches(0.25)):
    """Top-left small section label in neon green mono style."""
    add_text(slide, f"// {label_text}", Inches(0.55), y_offset,
             Inches(5), Inches(0.35), font_size=9.5, bold=False,
             color=NEON_GREEN, font_name="Courier New")

def slide_number(slide, num, total):
    add_text(slide, f"{num:02d} / {total:02d}",
             Inches(12.0), Inches(7.1), Inches(1.2), Inches(0.3),
             font_size=8, color=MUTED, align=PP_ALIGN.RIGHT, font_name="Courier New")

def bottom_bar(slide):
    add_rect(slide, 0, Inches(7.25), SLIDE_W, Inches(0.25), BORDER)
    add_text(slide, "VulnScan Pro  |  PBL Project  |  B.Tech Cybersecurity",
             Inches(0.4), Inches(7.28), Inches(10), Inches(0.2),
             font_size=7.5, color=MUTED, font_name="Calibri")

def green_accent_line(slide, y=Inches(0.62)):
    add_rect(slide, Inches(0.55), y, Inches(0.05), Inches(0.4), NEON_GREEN)

def slide_title(slide, title, sub=None, y=Inches(0.6)):
    green_accent_line(slide, y)
    add_text(slide, title, Inches(0.75), y, Inches(11.5), Inches(0.55),
             font_size=28, bold=True, color=WHITE, font_name="Calibri")
    if sub:
        add_text(slide, sub, Inches(0.75), y+Inches(0.52), Inches(11), Inches(0.35),
                 font_size=13, color=NEON_BLUE, font_name="Calibri", italic=True)

def bullet_box(slide, items, l, t, w, h,
               title=None, title_color=NEON_GREEN,
               item_size=12.5, bullet="▸", accent=NEON_GREEN):
    add_rect(slide, l, t, w, h, BG_CARD, line_color=BORDER, line_width=Pt(0.75))
    lines = []
    if title:
        lines.append({"text": title, "size": 12, "bold": True, "color": title_color,
                      "space_before": Pt(2)})
    for item in items:
        lines.append({"text": f"  {bullet}  {item}", "size": item_size, "bold": False,
                      "color": OFF_WHITE, "space_before": Pt(5)})
    add_textbox_multiline(slide, lines, l+Inches(0.15), t+Inches(0.12),
                          w-Inches(0.3), h-Inches(0.2))

def two_col_bullets(slide, left_items, right_items,
                    left_title="", right_title="",
                    top=Inches(1.35), height=Inches(5.4), item_size=12.5):
    col_w = Inches(6.0)
    bullet_box(slide, left_items,  Inches(0.4),  top, col_w, height,
               title=left_title, item_size=item_size)
    bullet_box(slide, right_items, Inches(6.9), top, col_w, height,
               title=right_title, item_size=item_size)


# ════════════════════════════════════════════════════════════════════════════
#  SLIDE BUILDERS
# ════════════════════════════════════════════════════════════════════════════

def make_title_slide(prs):
    slide = blank_slide(prs)
    fill_bg(slide)

    # Decorative top green stripe
    add_rect(slide, 0, 0, SLIDE_W, Inches(0.08), NEON_GREEN)
    # Subtle grid lines (horizontal)
    for i in range(3, 15):
        add_rect(slide, 0, Inches(i*0.5), SLIDE_W, Inches(0.005),
                 RGBColor(0x1A, 0x1A, 0x2E))

    # Shield icon text
    add_text(slide, "🛡", Inches(6.2), Inches(1.1), Inches(1.2), Inches(1.2),
             font_size=52, align=PP_ALIGN.CENTER)

    # Main title
    add_text(slide, "VulnScan Pro", Inches(1.5), Inches(2.2), Inches(10.3), Inches(1.0),
             font_size=54, bold=True, color=WHITE, align=PP_ALIGN.CENTER, font_name="Calibri")

    # Subtitle
    add_text(slide, "Automated Web Vulnerability Scanner & Intelligence Framework",
             Inches(1.5), Inches(3.1), Inches(10.3), Inches(0.6),
             font_size=17, color=NEON_BLUE, align=PP_ALIGN.CENTER, italic=True)

    # Divider line
    add_rect(slide, Inches(3.5), Inches(3.75), Inches(6.3), Inches(0.04), NEON_GREEN)

    # Tags row
    tags = [("12", "Scan Modules"), ("100%", "Test Accuracy"), ("OWASP", "Top 10 Mapped")]
    for i, (num, label) in enumerate(tags):
        x = Inches(2.8 + i*2.8)
        add_text(slide, num, x, Inches(3.9), Inches(2.5), Inches(0.55),
                 font_size=26, bold=True, color=NEON_GREEN, align=PP_ALIGN.CENTER)
        add_text(slide, label, x, Inches(4.38), Inches(2.5), Inches(0.35),
                 font_size=11, color=MUTED, align=PP_ALIGN.CENTER)

    # Bottom info
    add_rect(slide, 0, Inches(5.5), SLIDE_W, Inches(0.005), BORDER)
    add_text(slide, "PBL Project  •  B.Tech Cybersecurity  •  2025–26",
             Inches(1.5), Inches(5.6), Inches(10.3), Inches(0.4),
             font_size=11, color=MUTED, align=PP_ALIGN.CENTER)

    # Bottom green stripe
    add_rect(slide, 0, Inches(7.42), SLIDE_W, Inches(0.08), NEON_GREEN)
    return slide


def make_intro_slide(prs, num, total):
    slide = blank_slide(prs)
    fill_bg(slide)
    bottom_bar(slide)
    slide_number(slide, num, total)
    section_label(slide, "INTRODUCTION")
    slide_title(slide, "Introduction", "What is VulnScan Pro and why does it matter?")

    # Left: problem statement
    bullet_box(slide,
        ["Websites face thousands of automated attacks daily",
         "Manual security testing is slow, costly & expertise-heavy",
         "Most SMEs & developers lack access to enterprise security tools",
         "OWASP Top 10 threats remain unaddressed in most projects",
         "95% of cyber breaches exploit known, preventable vulnerabilities"],
        Inches(0.4), Inches(1.5), Inches(6.0), Inches(3.5),
        title="⚠  The Problem", title_color=RED_ACCENT, item_size=12)

    # Right: solution
    bullet_box(slide,
        ["Automated multi-module vulnerability scanner",
         "Scans for XSS, SQLi, CSRF, Open Redirect, WAF, Headers, SSL, DNS, Ports & more",
         "Real-time scan progress with live terminal logs",
         "Automated PDF report generation",
         "OWASP Top 10 compliance mapping",
         "Security scoring system (0–100 + letter grade)"],
        Inches(6.9), Inches(1.5), Inches(6.0), Inches(3.5),
        title="✅  Our Solution — VulnScan Pro", title_color=NEON_GREEN, item_size=12)

    # Bottom stat cards
    stats = [("Python", "Language"), ("Flask", "Backend"), ("12", "Modules"), ("SQLite", "Database"), ("ReportLab", "PDF Engine")]
    for i, (stat, lbl) in enumerate(stats):
        x = Inches(0.4 + i*2.58)
        add_rect(slide, x, Inches(5.2), Inches(2.4), Inches(0.9), BG_CARD, line_color=BORDER, line_width=Pt(0.75))
        add_text(slide, stat, x, Inches(5.28), Inches(2.4), Inches(0.4),
                 font_size=15, bold=True, color=NEON_BLUE, align=PP_ALIGN.CENTER)
        add_text(slide, lbl, x, Inches(5.65), Inches(2.4), Inches(0.3),
                 font_size=9, color=MUTED, align=PP_ALIGN.CENTER)
    return slide


def make_literature_slide(prs, num, total):
    slide = blank_slide(prs)
    fill_bg(slide)
    bottom_bar(slide)
    slide_number(slide, num, total)
    section_label(slide, "LITERATURE REVIEW")
    slide_title(slide, "Literature Review", "Prior work and tools that inspired VulnScan Pro")

    rows = [
        ("Nessus (Tenable)",       "Commercial network/web scanner. Expensive ($3,000+/yr). Closed-source.", "Inspired comprehensive module approach"),
        ("OWASP ZAP",              "Open-source proxy scanner. Complex setup, GUI-heavy, not API-native.",   "Inspired OWASP Top 10 compliance mapping"),
        ("Burp Suite",             "Industry standard pentesting suite. Requires manual operation & expertise.", "Inspired payload libraries for XSS/SQLi"),
        ("Nikto",                   "CLI-based web server scanner. No dashboard, no real-time stream, no PDF.", "Inspired tech fingerprinting module"),
        ("Skipfish (Google)",       "Fast automated scanner, discontinued. No active development.",            "Inspired crawler depth & form discovery"),
        ("Acunetix",                "Enterprise scanner with CI/CD integration. High cost, proprietary.",      "Inspired unified scoring & grading system"),
    ]

    add_rect(slide, Inches(0.4), Inches(1.45), Inches(12.5), Inches(0.35), BORDER)
    headers = ["Tool / Paper", "Limitation / Gap", "How VulnScan Pro Addresses It"]
    x_pos = [Inches(0.5), Inches(4.2), Inches(8.5)]
    for i, hdr in enumerate(headers):
        add_text(slide, hdr, x_pos[i], Inches(1.5), Inches(4.0), Inches(0.3),
                 font_size=10, bold=True, color=NEON_GREEN, font_name="Calibri")

    for ri, (tool, gap, addr) in enumerate(rows):
        y = Inches(1.85 + ri*0.77)
        bg = BG_CARD if ri % 2 == 0 else BG_DARK
        add_rect(slide, Inches(0.4), y, Inches(12.5), Inches(0.72), bg, line_color=BORDER, line_width=Pt(0.5))
        add_text(slide, tool, x_pos[0], y+Inches(0.05), Inches(3.6), Inches(0.62),
                 font_size=11, bold=True, color=NEON_BLUE)
        add_text(slide, gap, x_pos[1], y+Inches(0.05), Inches(4.2), Inches(0.62),
                 font_size=10, color=OFF_WHITE)
        add_text(slide, addr, x_pos[2], y+Inches(0.05), Inches(4.2), Inches(0.62),
                 font_size=10, color=NEON_GREEN)
    return slide


def make_subject_integration_slide(prs, num, total):
    slide = blank_slide(prs)
    fill_bg(slide)
    bottom_bar(slide)
    slide_number(slide, num, total)
    section_label(slide, "SUBJECT INTEGRATION")
    slide_title(slide, "Subject Integration Overview")

    subjects = [
        ("CS23601", "Blockchain &\nCryptography",       "SSL/TLS Scanner — audits certificate validity,\ncipher suites, TLS version, HSTS enforcement",    NEON_BLUE),
        ("CS23602", "SIEM & SOAR",                      "Notifier Pipeline — auto-sends alerts via\nSlack Webhook and Email on scan completion",         GOLD),
        ("CS23603", "Cyber Threat\nManagement",         "Crawler + Port Scanner + WAF Detector —\nmaps attack surface, scores threat exposure",          RED_ACCENT),
        ("CS23604", "Authentication &\nIdentity Mgmt",  "JS Analyzer + Header Scanner — detects\nhardcoded API keys & insecure session cookies",         ORANGE),
        ("CS23605", "Security Compliance\n& Audit Mgmt","OWASP Mapper + PDF Report — auto-generates\nOWASP Top 10 compliance audit documents",            NEON_GREEN),
        ("CS23607", "Internet of\nThings (IoT)",        "Port Scanner + Tech Fingerprinting — maps\nIoT device admin ports and detects firmware CVEs",    RGBColor(0xA7,0x8B,0xFA)),
    ]

    for i, (code, name, desc, col) in enumerate(subjects):
        row = i // 3
        col_pos = i % 3
        x = Inches(0.35 + col_pos * 4.35)
        y = Inches(1.45 + row * 2.8)
        w, h = Inches(4.1), Inches(2.55)

        add_rect(slide, x, y, w, h, BG_CARD, line_color=col, line_width=Pt(1.0))
        add_rect(slide, x, y, w, Inches(0.07), col)   # top colour stripe

        add_text(slide, code, x+Inches(0.15), y+Inches(0.14), w-Inches(0.3), Inches(0.28),
                 font_size=9, bold=True, color=col, font_name="Courier New")
        add_text(slide, name, x+Inches(0.15), y+Inches(0.38), w-Inches(0.3), Inches(0.65),
                 font_size=13, bold=True, color=WHITE)
        add_text(slide, desc, x+Inches(0.15), y+Inches(1.0), w-Inches(0.3), Inches(1.4),
                 font_size=10.5, color=OFF_WHITE)
    return slide


def make_design_methodology_slide(prs, num, total):
    slide = blank_slide(prs)
    fill_bg(slide)
    bottom_bar(slide)
    slide_number(slide, num, total)
    section_label(slide, "DESIGN & METHODOLOGY")
    slide_title(slide, "Design and Methodology", "Agile sprint-based development with TDD approach")

    phases = [
        ("01", "Requirements\nAnalysis",    "Identified OWASP Top 10\nvulnerability classes.\nDefined module scope.", NEON_GREEN),
        ("02", "System Design",             "Designed REST API,\ndatabase schema, and\nmodular scanner pipeline.", NEON_BLUE),
        ("03", "Module\nDevelopment",       "Built 12 scanners as\nindependent Python modules\nwith standard interfaces.", GOLD),
        ("04", "Backend\nOrchestration",    "Flask backend with\nbg thread, SSE streaming\n& SQLite persistence.", ORANGE),
        ("05", "Frontend\nDevelopment",     "Glassmorphism dark-theme\ndashboard with Chart.js\n& real-time log terminal.", RGBColor(0xA7,0x8B,0xFA)),
        ("06", "Testing &\nValidation",     "47 test cases on\ndeliberately vulnerable\nFlask server → 100% accuracy.", RED_ACCENT),
    ]

    for i, (num_lbl, title, desc, col) in enumerate(phases):
        x = Inches(0.35 + (i % 3)*4.35)
        y = Inches(1.45 + (i // 3)*2.75)
        w, h = Inches(4.1), Inches(2.5)
        add_rect(slide, x, y, w, h, BG_CARD, line_color=BORDER, line_width=Pt(0.75))
        add_text(slide, num_lbl, x+Inches(0.15), y+Inches(0.1), Inches(0.7), Inches(0.55),
                 font_size=28, bold=True, color=col, font_name="Courier New")
        add_text(slide, title, x+Inches(0.15), y+Inches(0.6), w-Inches(0.3), Inches(0.6),
                 font_size=13, bold=True, color=WHITE)
        add_text(slide, desc, x+Inches(0.15), y+Inches(1.18), w-Inches(0.3), Inches(1.2),
                 font_size=10.5, color=OFF_WHITE)
    return slide


def make_architecture_slide(prs, num, total):
    slide = blank_slide(prs)
    fill_bg(slide)
    bottom_bar(slide)
    slide_number(slide, num, total)
    section_label(slide, "SYSTEM ARCHITECTURE")
    slide_title(slide, "System Architecture", "Three-tier client-server architecture")

    layers = [
        ("PRESENTATION LAYER",  "Browser · index.html · results.html",
         "Glassmorphism UI  |  Chart.js Doughnut  |  SSE Real-time Log  |  Severity Filter  |  PDF Export",
         NEON_BLUE,   Inches(1.5)),
        ("APPLICATION LAYER",   "Flask Backend · app.py · REST API",
         "POST /api/scan  |  GET /stream (SSE)  |  GET /results  |  Threading  |  OWASP Mapper  |  Score Engine",
         NEON_GREEN,  Inches(2.9)),
        ("SCANNER ENGINE",      "12 Independent Python Scan Modules",
         "Crawler · XSS · SQLi · CSRF · Open Redirect · WAF · Headers · SSL · DNS · Ports · Tech · JS Analyzer",
         GOLD,        Inches(4.3)),
        ("DATA LAYER",          "SQLite DB · PDF Reports · Notifications",
         "ScanTask Model  |  ScanEvent Log  |  ReportLab PDF  |  Slack Webhook  |  SMTP Email",
         ORANGE,      Inches(5.7)),
    ]

    arrow_y_positions = [Inches(2.82), Inches(4.22), Inches(5.62)]

    for (layer, subtitle, detail, col, y) in layers:
        add_rect(slide, Inches(0.9), y, Inches(11.5), Inches(1.15), BG_CARD, line_color=col, line_width=Pt(1.0))
        add_rect(slide, Inches(0.9), y, Inches(0.06), Inches(1.15), col)
        add_text(slide, layer, Inches(1.1), y+Inches(0.07), Inches(3.5), Inches(0.38),
                 font_size=10, bold=True, color=col, font_name="Courier New")
        add_text(slide, subtitle, Inches(1.1), y+Inches(0.44), Inches(3.5), Inches(0.35),
                 font_size=11, bold=True, color=WHITE)
        add_text(slide, detail, Inches(4.9), y+Inches(0.3), Inches(7.3), Inches(0.65),
                 font_size=10, color=OFF_WHITE)

    for ay in arrow_y_positions:
        add_text(slide, "▼", Inches(6.5), ay, Inches(0.4), Inches(0.35),
                 font_size=14, color=MUTED, align=PP_ALIGN.CENTER)
    return slide


def make_implementation_slide(prs, num, total):
    slide = blank_slide(prs)
    fill_bg(slide)
    bottom_bar(slide)
    slide_number(slide, num, total)
    section_label(slide, "IMPLEMENTATION")
    slide_title(slide, "Implementation", "12 independent scanner modules + unified orchestration")

    modules = [
        ("🌐", "Crawler",          "BFS link discovery\nForm & JS extraction"),
        ("💉", "XSS Scanner",      "60+ payloads across\n8 attack categories"),
        ("🗄", "SQLi Scanner",     "Error / Boolean /\nTime-based detection"),
        ("🔒", "SSL/TLS",          "Cert validity,\nweak cipher detection"),
        ("🌍", "DNS Recon",         "A, MX, NS, TXT,\nSPF, DMARC records"),
        ("🔌", "Port Scanner",     "30 critical ports\nservice risk mapping"),
        ("📜", "Header Scanner",   "8 security headers\ncookie flag checks"),
        ("🛡", "WAF Detector",     "Signature-based\nfirewall detection"),
        ("🔗", "Open Redirect",    "URL param & form\nredirect testing"),
        ("🔑", "CSRF Scanner",     "CSRF token absence\ndetection on POSTs"),
        ("🔍", "Tech Fingerprint", "CMS, server, libs\nCVE lookup"),
        ("📁", "JS Analyzer",      "Secret & credential\nregex detection"),
    ]

    cols = 4
    for i, (icon, name, desc) in enumerate(modules):
        row = i // cols
        col = i % cols
        x = Inches(0.35 + col*3.24)
        y = Inches(1.45 + row*1.85)
        w, h = Inches(3.05), Inches(1.7)
        add_rect(slide, x, y, w, h, BG_CARD, line_color=BORDER, line_width=Pt(0.75))
        add_text(slide, icon, x+Inches(0.12), y+Inches(0.1), Inches(0.5), Inches(0.5), font_size=18)
        add_text(slide, name, x+Inches(0.55), y+Inches(0.12), w-Inches(0.65), Inches(0.38),
                 font_size=12, bold=True, color=NEON_GREEN)
        add_text(slide, desc, x+Inches(0.12), y+Inches(0.6), w-Inches(0.25), Inches(0.95),
                 font_size=10.5, color=OFF_WHITE)
    return slide


def make_results_slide(prs, num, total):
    slide = blank_slide(prs)
    fill_bg(slide)
    bottom_bar(slide)
    slide_number(slide, num, total)
    section_label(slide, "RESULTS")
    slide_title(slide, "Results & Testing", "100% backtest accuracy across 47 automated test cases")

    # Accuracy table
    rows = [
        ("Header Scanner",    "9",  "9",  "100%", NEON_GREEN),
        ("XSS Scanner",       "2",  "2",  "100%", NEON_GREEN),
        ("SQL Injection",      "2",  "2",  "100%", NEON_GREEN),
        ("Crawler",            "6",  "6",  "100%", NEON_GREEN),
        ("Tech Fingerprinting","5",  "5",  "100%", NEON_GREEN),
        ("JS Analyzer",        "7",  "7",  "100%", NEON_GREEN),
        ("Port Scanner",       "1",  "1",  "100%", NEON_GREEN),
        ("DNS Recon",          "3",  "3",  "100%", NEON_GREEN),
        ("SSL Scanner",        "4",  "4",  "100%", NEON_GREEN),
        ("WAF Detector",       "2",  "2",  "100%", NEON_GREEN),
        ("Open Redirect",      "3",  "3",  "100%", NEON_GREEN),
        ("CSRF Scanner",       "3",  "3",  "100%", NEON_GREEN),
    ]

    # Header
    hdr_cols = [("Module", Inches(0.5)), ("Tests", Inches(5.2)), ("Pass", Inches(6.3)), ("Accuracy", Inches(7.2))]
    add_rect(slide, Inches(0.4), Inches(1.45), Inches(8.7), Inches(0.38), BORDER)
    for label, xp in hdr_cols:
        add_text(slide, label, xp, Inches(1.5), Inches(1.5), Inches(0.3),
                 font_size=10, bold=True, color=NEON_GREEN)

    for ri, (mod, tests, passes, acc, col) in enumerate(rows):
        y = Inches(1.85 + ri*0.4)
        bg = BG_CARD if ri % 2 == 0 else BG_DARK
        add_rect(slide, Inches(0.4), y, Inches(8.7), Inches(0.38), bg, line_color=BORDER, line_width=Pt(0.4))
        add_text(slide, mod,   Inches(0.5), y+Inches(0.04), Inches(4.5), Inches(0.3), font_size=10.5, color=OFF_WHITE)
        add_text(slide, tests, Inches(5.2), y+Inches(0.04), Inches(0.9), Inches(0.3), font_size=10.5, color=OFF_WHITE, align=PP_ALIGN.CENTER)
        add_text(slide, passes,Inches(6.3), y+Inches(0.04), Inches(0.8), Inches(0.3), font_size=10.5, color=OFF_WHITE, align=PP_ALIGN.CENTER)
        add_text(slide, acc,   Inches(7.2), y+Inches(0.04), Inches(1.7), Inches(0.3), font_size=10.5, bold=True, color=col, align=PP_ALIGN.CENTER)

    # Total row
    add_rect(slide, Inches(0.4), Inches(6.66), Inches(8.7), Inches(0.38), NEON_GREEN)
    add_text(slide, "TOTAL  —  47 / 47  —  100% Overall Accuracy",
             Inches(0.5), Inches(6.7), Inches(8.5), Inches(0.3),
             font_size=11, bold=True, color=BG_DARK, align=PP_ALIGN.CENTER)

    # Right side highlights
    highlights = [
        ("47", "Total Test Cases"),
        ("12", "Modules Tested"),
        ("100%", "Overall Accuracy"),
        ("0", "False Negatives"),
    ]
    for i, (val, lbl) in enumerate(highlights):
        y = Inches(1.45 + i*1.45)
        add_rect(slide, Inches(9.5), y, Inches(3.4), Inches(1.25), BG_CARD, line_color=NEON_GREEN, line_width=Pt(0.75))
        add_text(slide, val, Inches(9.5), y+Inches(0.05), Inches(3.4), Inches(0.7),
                 font_size=34, bold=True, color=NEON_GREEN, align=PP_ALIGN.CENTER)
        add_text(slide, lbl, Inches(9.5), y+Inches(0.78), Inches(3.4), Inches(0.35),
                 font_size=10, color=MUTED, align=PP_ALIGN.CENTER)
    return slide


def make_industry_slide(prs, num, total):
    slide = blank_slide(prs)
    fill_bg(slide)
    bottom_bar(slide)
    slide_number(slide, num, total)
    section_label(slide, "INDUSTRY RELEVANCE")
    slide_title(slide, "Industry Relevance", "Real-world alignment with cybersecurity industry needs")

    two_col_bullets(slide,
        left_items=[
            "Penetration testing firms can use VulnScan Pro for automated initial reconnaissance",
            "DevSecOps teams can integrate the API into CI/CD pipelines for shift-left security",
            "Bug bounty hunters can rapidly map attack surfaces before manual testing",
            "SMEs with no security budget get enterprise-grade scanning for free",
            "Security auditors can generate instant OWASP-aligned PDF compliance reports",
            "SOC teams can automate periodic scanning and route alerts to Slack/SIEM",
        ],
        right_items=[
            "Comparable to: Nessus · OWASP ZAP · Acunetix · Burp Suite Community",
            "Global Cybersecurity market: $266.2 Billion by 2027 (CAGR 10.9%)",
            "Average cost of a data breach in 2024: $4.88 Million (IBM Report)",
            "86% of breaches involve web application vulnerabilities (Verizon DBIR)",
            "95% of vulnerabilities exploited are already in the NVD/CVE database",
            "Automated scanners reduce vulnerability detection time by 70% vs manual",
        ],
        left_title="🏭  Use Cases",
        right_title="📊  Industry Statistics",
        item_size=11.5
    )
    return slide


def make_challenges_slide(prs, num, total):
    slide = blank_slide(prs)
    fill_bg(slide)
    bottom_bar(slide)
    slide_number(slide, num, total)
    section_label(slide, "CHALLENGES")
    slide_title(slide, "Challenges Faced", "Technical and design problems encountered and solved")

    challenges = [
        ("False Positives in XSS",
         "Attribute injection payloads without quotes (e.g. x onmouseover=alert(1)) reflected identically in safe forms.",
         "Updated attr_injection payloads to include quote characters (\", ') so HTML escaping triggers correctly. Now 100% accuracy.",
         RED_ACCENT),
        ("Real-time Log Streaming",
         "WebSockets require separate server infrastructure. Maintaining live updates across request cycles was complex.",
         "Implemented Server-Sent Events (SSE) — a simpler HTTP-based push protocol. Backend polls DB every 1s and streams events.",
         NEON_BLUE),
        ("Thread-Safe DB Access",
         "SQLAlchemy sessions are not thread-safe. Scanner threads writing simultaneously caused integrity errors.",
         "Each background operation creates its own app_context() ensuring isolated SQLAlchemy sessions per thread.",
         GOLD),
        ("Scan Accuracy vs Speed",
         "More aggressive crawling and testing increased detection but timed out on fast-rate-limited targets.",
         "Added per-request timeouts (5s), depth limiting for crawler (max_depth=2), and skip logic for empty forms.",
         ORANGE),
        ("Dynamic JS-Rendered Pages",
         "Websites built with React/Angular/Vue render HTML via JavaScript — requests-based crawler cannot see this content.",
         "Acknowledged as a current limitation. Future plan: integrate Playwright for headless browser-based crawling.",
         RGBColor(0xA7,0x8B,0xFA)),
        ("PDF Report Formatting",
         "ReportLab's low-level canvas API required pixel-precise manual layout for tables, badges and vulnerability cards.",
         "Built reusable helper functions for drawing tables, headers and section dividers — significantly reduced code duplication.",
         NEON_GREEN),
    ]

    for i, (title, problem, solution, col) in enumerate(challenges):
        row, c = divmod(i, 2)
        x = Inches(0.35 + c*6.5)
        y = Inches(1.45 + row*1.95)
        w, h = Inches(6.2), Inches(1.82)
        add_rect(slide, x, y, w, h, BG_CARD, line_color=col, line_width=Pt(0.75))
        add_rect(slide, x, y, w, Inches(0.055), col)
        add_text(slide, title, x+Inches(0.15), y+Inches(0.1), w-Inches(0.3), Inches(0.35),
                 font_size=11.5, bold=True, color=col)
        add_text(slide, f"⚠  {problem}", x+Inches(0.15), y+Inches(0.44), w-Inches(0.3), Inches(0.55),
                 font_size=9.5, color=RGBColor(0xFF,0xCC,0x88))
        add_text(slide, f"✅  {solution}", x+Inches(0.15), y+Inches(1.0), w-Inches(0.3), Inches(0.7),
                 font_size=9.5, color=NEON_GREEN)
    return slide


def make_ethical_slide(prs, num, total):
    slide = blank_slide(prs)
    fill_bg(slide)
    bottom_bar(slide)
    slide_number(slide, num, total)
    section_label(slide, "ETHICAL CONSIDERATIONS")
    slide_title(slide, "Ethical Considerations", "Responsible disclosure and legal usage framework")

    two_col_bullets(slide,
        left_items=[
            "Authorization checkbox mandated — user must confirm written consent before any scan can be initiated",
            "Tool tested exclusively on intentionally vulnerable local servers (vuln_target.py) and public legal targets (testphp.vulnweb.com)",
            "No scan data is transmitted to external servers — all results stored locally in SQLite",
            "Payloads are detection-only — we do not exploit, exfiltrate data, or cause damage to target systems",
            "Tool explicitly states: 'For authorized internal and contracted security evaluations only'",
            "Compliant with CERT-In guidelines and the IT Act 2000 (Section 43/66) for authorized testing",
        ],
        right_items=[
            "Dual-use technology challenge: legitimate security tool vs potential misuse",
            "Responsible Disclosure: any vulnerabilities found on authorized targets should be reported to the owner immediately",
            "Do NOT scan government, banking, or public infrastructure without explicit written permission",
            "Rate-limiting logic prevents accidental DoS conditions on target servers",
            "All team members trained in ethical hacking guidelines before project development",
            "Full audit trail maintained — every scan is logged with timestamp, scan ID, and target URL",
        ],
        left_title="🛡  Controls Built Into the Tool",
        right_title="⚖  Ethical Framework & Guidelines",
        item_size=11.5
    )
    return slide


def make_future_scope_slide(prs, num, total):
    slide = blank_slide(prs)
    fill_bg(slide)
    bottom_bar(slide)
    slide_number(slide, num, total)
    section_label(slide, "FUTURE SCOPE")
    slide_title(slide, "Future Scope", "Next-generation enhancements planned for VulnScan Pro")

    items = [
        ("🤖", "AI-Powered\nVuln Prediction",     "ML model trained on CVE database to\npredict likely vulnerabilities based on\ndetected tech stack and version data.",         NEON_GREEN),
        ("🌐", "Authenticated\nScanning",          "Login session support using Selenium/\nPlaywright to scan pages behind auth\nwalls — vastly expanding coverage.",             NEON_BLUE),
        ("⚡", "CI/CD Pipeline\nIntegration",      "GitHub Actions / Jenkins plugin so\ndevelopers scan their own apps on\nevery code push (shift-left security).",            GOLD),
        ("📡", "Real-time CVE\nFeed Integration",  "Connect to NVD API and MITRE CVE\ndatabase for live CVE lookup instead\nof a static local knowledge base.",               ORANGE),
        ("🔄", "Scheduled Scans\n& Alerting",       "Cron-based recurring scans with delta\nreporting — only alerting on NEW\nvulnerabilities since last scan.",                RGBColor(0xA7,0x8B,0xFA)),
        ("📱", "Mobile App\nDashboard",             "React Native companion app for real-\ntime scan monitoring and push\nnotifications for critical findings.",                RED_ACCENT),
    ]

    for i, (icon, title, desc, col) in enumerate(items):
        row, c = divmod(i, 3)
        x = Inches(0.35 + c*4.35)
        y = Inches(1.45 + row*2.7)
        w, h = Inches(4.1), Inches(2.5)
        add_rect(slide, x, y, w, h, BG_CARD, line_color=col, line_width=Pt(0.85))
        add_text(slide, icon, x+Inches(0.15), y+Inches(0.1), Inches(0.6), Inches(0.5), font_size=22)
        add_text(slide, title, x+Inches(0.65), y+Inches(0.1), w-Inches(0.8), Inches(0.6),
                 font_size=12.5, bold=True, color=col)
        add_text(slide, desc, x+Inches(0.15), y+Inches(0.72), w-Inches(0.3), Inches(1.6),
                 font_size=10.5, color=OFF_WHITE)
    return slide


def make_conclusion_slide(prs, num, total):
    slide = blank_slide(prs)
    fill_bg(slide)
    bottom_bar(slide)
    slide_number(slide, num, total)
    section_label(slide, "CONCLUSION")
    slide_title(slide, "Conclusion")

    add_text(slide,
        "VulnScan Pro successfully delivers a comprehensive, automated, open-source web vulnerability scanning "
        "framework built entirely in Python. It integrates 12 scanning modules, real-time SSE-based progress streaming, "
        "an intelligent scoring engine, OWASP Top 10 compliance mapping, and automated PDF report generation — all "
        "within a modern glassmorphism web interface.",
        Inches(0.5), Inches(1.45), Inches(12.3), Inches(1.0),
        font_size=12.5, color=OFF_WHITE)

    achievements = [
        "✅  12 scanner modules built from scratch in Python",
        "✅  100% accuracy on 47 automated backtest cases",
        "✅  Full OWASP Top 10 vulnerability coverage",
        "✅  Real-time scan monitoring via Server-Sent Events",
        "✅  Automated, professional PDF security reports",
        "✅  Subject integration across all 6 course modules (CS23601–CS23607)",
    ]
    bullet_box(slide, achievements, Inches(0.5), Inches(2.55), Inches(7.8), Inches(3.8),
               title="Key Achievements", item_size=12.5, bullet="")

    # Right: closing statement card
    add_rect(slide, Inches(8.7), Inches(2.55), Inches(4.25), Inches(3.8), BG_CARD, line_color=NEON_GREEN, line_width=Pt(1.0))
    add_rect(slide, Inches(8.7), Inches(2.55), Inches(4.25), Inches(0.07), NEON_GREEN)
    add_text(slide, "\"Security is not a product\nbut a process.\"\n— Bruce Schneier",
             Inches(8.85), Inches(2.72), Inches(3.95), Inches(1.5),
             font_size=14, italic=True, color=NEON_GREEN, align=PP_ALIGN.CENTER)
    add_rect(slide, Inches(9.5), Inches(4.3), Inches(2.7), Inches(0.03), MUTED)
    add_text(slide,
        "VulnScan Pro automates\nthat process — giving developers\nand security teams a free,\npowerful tool to continuously\nmonitor and improve their\nweb security posture.",
        Inches(8.85), Inches(4.45), Inches(3.95), Inches(1.7),
        font_size=11, color=OFF_WHITE, align=PP_ALIGN.CENTER)
    return slide


def make_references_slide(prs, num, total):
    slide = blank_slide(prs)
    fill_bg(slide)
    bottom_bar(slide)
    slide_number(slide, num, total)
    section_label(slide, "REFERENCES")
    slide_title(slide, "References")

    refs = [
        "[1]  OWASP Foundation, \"OWASP Top 10 — 2021: The Ten Most Critical Web Application Security Risks,\" owasp.org, 2021.",
        "[2]  IBM Security, \"Cost of a Data Breach Report 2024,\" IBM Corporation, 2024. [Online] ibm.com/security/data-breach",
        "[3]  Verizon, \"2024 Data Breach Investigations Report (DBIR),\" Verizon Business, 2024.",
        "[4]  NIST, \"National Vulnerability Database (NVD),\" nvd.nist.gov. (CVE reference database)",
        "[5]  Pallets Projects, \"Flask Documentation v3.0,\" flask.palletsprojects.com, 2024.",
        "[6]  Python Software Foundation, \"Python 3 Documentation,\" docs.python.org, 2024.",
        "[7]  Tenable, \"Nessus Vulnerability Scanner,\" tenable.com/products/nessus — used as competitive reference.",
        "[8]  PortSwigger, \"Web Security Academy & Burp Suite,\" portswigger.net — payload and methodology reference.",
        "[9]  Chart.js Contributors, \"Chart.js v4 Documentation,\" chartjs.org, 2024.",
        "[10] ReportLab Inc., \"ReportLab PDF Library Documentation,\" reportlab.com, 2024.",
        "[11] CERT-In, \"Guidelines for Ethical Hacking and Penetration Testing,\" cert-in.org.in, Govt. of India.",
        "[12] M. Howard & D. LeBlanc, \"Writing Secure Code,\" 2nd ed., Microsoft Press, 2002.",
    ]

    for i, ref in enumerate(refs):
        y = Inches(1.45 + i*0.465)
        bg = BG_CARD if i % 2 == 0 else BG_DARK
        add_rect(slide, Inches(0.4), y, Inches(12.5), Inches(0.43), bg)
        add_text(slide, ref, Inches(0.55), y+Inches(0.05), Inches(12.2), Inches(0.35),
                 font_size=10, color=OFF_WHITE)
    return slide


# ════════════════════════════════════════════════════════════════════════════
#  MAIN
# ════════════════════════════════════════════════════════════════════════════

def main():
    prs = new_prs()
    TOTAL = 13   # Title + 12 content slides

    make_title_slide(prs)
    make_intro_slide(prs, 1, TOTAL)
    make_literature_slide(prs, 2, TOTAL)
    make_subject_integration_slide(prs, 3, TOTAL)
    make_design_methodology_slide(prs, 4, TOTAL)
    make_architecture_slide(prs, 5, TOTAL)
    make_implementation_slide(prs, 6, TOTAL)
    make_results_slide(prs, 7, TOTAL)
    make_industry_slide(prs, 8, TOTAL)
    make_challenges_slide(prs, 9, TOTAL)
    make_ethical_slide(prs, 10, TOTAL)
    make_future_scope_slide(prs, 11, TOTAL)
    make_conclusion_slide(prs, 12, TOTAL)
    make_references_slide(prs, 13, TOTAL)

    out = r"D:\Nessus 2.0\vulnscan-pro\VulnScan_Pro_PBL_Presentation.pptx"
    prs.save(out)
    print(f"[OK] Presentation saved -> {out}")
    print(f"[OK] Total slides: {len(prs.slides)}")

if __name__ == "__main__":
    main()
