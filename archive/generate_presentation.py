from pptx import Presentation
from pptx.util import Inches, Pt, Emu
from pptx.dml.color import RGBColor
from pptx.enum.text import PP_ALIGN, MSO_ANCHOR
from pptx.enum.shapes import MSO_SHAPE
import os

prs = Presentation()
prs.slide_width = Inches(13.333)
prs.slide_height = Inches(7.5)

# ═══════════════════════════════════════════
#   DESIGN TOKENS
# ═══════════════════════════════════════════
BG_WHITE       = RGBColor(0xFA, 0xFA, 0xFC)
BG_LIGHT_GRAY  = RGBColor(0xF2, 0xF4, 0xF7)
TEXT_DARK       = RGBColor(0x1A, 0x1A, 0x2E)
TEXT_MEDIUM     = RGBColor(0x4A, 0x4A, 0x68)
TEXT_LIGHT      = RGBColor(0x6B, 0x70, 0x80)
ACCENT_BLUE     = RGBColor(0x25, 0x63, 0xEB)
ACCENT_INDIGO   = RGBColor(0x4F, 0x46, 0xE5)
ACCENT_CYAN     = RGBColor(0x06, 0xB6, 0xD4)
ACCENT_GREEN    = RGBColor(0x10, 0xB9, 0x81)
ACCENT_RED      = RGBColor(0xEF, 0x44, 0x44)
ACCENT_ORANGE   = RGBColor(0xF5, 0x9E, 0x0B)
ACCENT_PURPLE   = RGBColor(0x8B, 0x5C, 0xF6)
WHITE           = RGBColor(0xFF, 0xFF, 0xFF)
BORDER_LIGHT    = RGBColor(0xE2, 0xE8, 0xF0)

FONT_TITLE   = "Segoe UI"
FONT_BODY    = "Segoe UI"
FONT_CODE    = "Cascadia Code"

def add_bg(slide, color=BG_WHITE):
    bg = slide.background
    fill = bg.fill
    fill.solid()
    fill.fore_color.rgb = color

def add_shape(slide, left, top, width, height, fill_color, border_color=None, radius=None):
    shape = slide.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, left, top, width, height)
    shape.fill.solid()
    shape.fill.fore_color.rgb = fill_color
    if border_color:
        shape.line.color.rgb = border_color
        shape.line.width = Pt(1)
    else:
        shape.line.fill.background()
    return shape

def add_text_box(slide, left, top, width, height, text, font_size=14, color=TEXT_DARK, bold=False, alignment=PP_ALIGN.LEFT, font_name=FONT_BODY):
    txBox = slide.shapes.add_textbox(left, top, width, height)
    tf = txBox.text_frame
    tf.word_wrap = True
    p = tf.paragraphs[0]
    p.text = text
    p.font.size = Pt(font_size)
    p.font.color.rgb = color
    p.font.bold = bold
    p.font.name = font_name
    p.alignment = alignment
    return txBox

def add_multi_text(slide, left, top, width, height, lines):
    """lines = [(text, font_size, color, bold, font_name), ...]"""
    txBox = slide.shapes.add_textbox(left, top, width, height)
    tf = txBox.text_frame
    tf.word_wrap = True
    for i, (text, size, color, bold, fname) in enumerate(lines):
        if i == 0:
            p = tf.paragraphs[0]
        else:
            p = tf.add_paragraph()
        p.text = text
        p.font.size = Pt(size)
        p.font.color.rgb = color
        p.font.bold = bold
        p.font.name = fname
        p.space_after = Pt(4)
    return txBox

def add_accent_bar(slide, left, top, width, height, color):
    shape = slide.shapes.add_shape(MSO_SHAPE.RECTANGLE, left, top, width, height)
    shape.fill.solid()
    shape.fill.fore_color.rgb = color
    shape.line.fill.background()
    return shape

def add_icon_card(slide, left, top, width, height, icon_text, title, desc, accent_color, bg_color=WHITE):
    card = add_shape(slide, left, top, width, height, bg_color, BORDER_LIGHT)
    add_accent_bar(slide, left, top, width, Pt(4), accent_color)
    add_text_box(slide, left + Inches(0.3), top + Inches(0.2), width - Inches(0.6), Inches(0.5), icon_text, 22, accent_color, True)
    add_text_box(slide, left + Inches(0.3), top + Inches(0.65), width - Inches(0.6), Inches(0.4), title, 13, TEXT_DARK, True)
    add_text_box(slide, left + Inches(0.3), top + Inches(1.0), width - Inches(0.6), height - Inches(1.2), desc, 10.5, TEXT_MEDIUM, False)

def add_code_block(slide, left, top, width, height, code_text, accent=ACCENT_BLUE):
    bg = add_shape(slide, left, top, width, height, RGBColor(0xF8, 0xFA, 0xFC), BORDER_LIGHT)
    add_accent_bar(slide, left, top, Pt(4), height, accent)
    add_text_box(slide, left + Inches(0.3), top + Inches(0.15), width - Inches(0.5), height - Inches(0.3), code_text, 10, TEXT_DARK, False, PP_ALIGN.LEFT, FONT_CODE)


# ═══════════════════════════════════════════
#   SLIDE 1: TITLE
# ═══════════════════════════════════════════
slide = prs.slides.add_slide(prs.slide_layouts[6])
add_bg(slide, BG_WHITE)

# gradient-like accent strip on top
add_accent_bar(slide, Inches(0), Inches(0), prs.slide_width, Inches(0.08), ACCENT_BLUE)

# left side content
add_text_box(slide, Inches(1.2), Inches(1.8), Inches(6), Inches(0.5), "🛡️  VULNSCAN PRO", 16, ACCENT_BLUE, True)
add_text_box(slide, Inches(1.2), Inches(2.4), Inches(7), Inches(1.2), "Intelligent Web\nVulnerability Scanner", 44, TEXT_DARK, True)
add_text_box(slide, Inches(1.2), Inches(4.0), Inches(7), Inches(0.8), "A multi-vector security framework combining deep reconnaissance,\nblind injection detection, and intelligent payload analysis.", 15, TEXT_MEDIUM, False)

# metric cards
for i, (val, label) in enumerate([("9", "Scanner Modules"), ("100%", "Backtest Accuracy"), ("32+", "XSS Payloads"), ("6", "SQLi Techniques")]):
    left = Inches(1.2) + Inches(i * 2.5)
    card = add_shape(slide, left, Inches(5.2), Inches(2.2), Inches(1.2), WHITE, BORDER_LIGHT)
    add_text_box(slide, left + Inches(0.3), Inches(5.35), Inches(1.6), Inches(0.5), val, 28, ACCENT_BLUE, True, PP_ALIGN.LEFT)
    add_text_box(slide, left + Inches(0.3), Inches(5.85), Inches(1.6), Inches(0.4), label, 11, TEXT_MEDIUM, False, PP_ALIGN.LEFT)

# right side accent decoration
accent_box = add_shape(slide, Inches(9.5), Inches(1.5), Inches(3), Inches(4.5), BG_LIGHT_GRAY, BORDER_LIGHT)
add_text_box(slide, Inches(9.8), Inches(2.0), Inches(2.5), Inches(3.5),
    "$ vulnscan --target example.com\n\n"
    "[✓] Crawler: 47 pages mapped\n"
    "[✓] XSS: 3 reflected sinks found\n"
    "[✓] SQLi: Blind time-based detected\n"
    "[✓] DNS: 5 subdomains found\n"
    "[✓] SSL: Certificate valid\n"
    "[✓] Headers: 4 missing\n\n"
    "Score: B+ (78/100)", 11, TEXT_DARK, False, PP_ALIGN.LEFT, FONT_CODE)


# ═══════════════════════════════════════════
#   SLIDE 2: THE PROBLEM
# ═══════════════════════════════════════════
slide = prs.slides.add_slide(prs.slide_layouts[6])
add_bg(slide, BG_WHITE)
add_accent_bar(slide, Inches(0), Inches(0), prs.slide_width, Inches(0.08), ACCENT_RED)

add_text_box(slide, Inches(1), Inches(0.6), Inches(5), Inches(0.4), "THE PROBLEM", 13, ACCENT_RED, True)
add_text_box(slide, Inches(1), Inches(1.0), Inches(8), Inches(0.8), "Why Web Security Can't Be An Afterthought", 32, TEXT_DARK, True)

stats = [
    ("$4.45M", "Average cost of a\ndata breach in 2023", "— IBM Security Report", ACCENT_RED),
    ("43%", "Of cyberattacks target\nsmall businesses", "— Verizon DBIR 2023", ACCENT_ORANGE),
    ("74%", "Of web apps have at least\none critical vulnerability", "— HCL AppScan Report", ACCENT_PURPLE),
    ("280 days", "Average time to identify\nand contain a breach", "— IBM Security Report", ACCENT_BLUE),
]
for i, (val, desc, source, color) in enumerate(stats):
    left = Inches(0.8) + Inches(i * 3.1)
    card = add_shape(slide, left, Inches(2.3), Inches(2.8), Inches(2.4), WHITE, BORDER_LIGHT)
    add_accent_bar(slide, left, Inches(2.3), Inches(2.8), Pt(4), color)
    add_text_box(slide, left + Inches(0.3), Inches(2.6), Inches(2.2), Inches(0.6), val, 32, color, True)
    add_text_box(slide, left + Inches(0.3), Inches(3.3), Inches(2.2), Inches(0.7), desc, 13, TEXT_DARK, False)
    add_text_box(slide, left + Inches(0.3), Inches(4.1), Inches(2.2), Inches(0.3), source, 9, TEXT_LIGHT, False)

# bottom takeaway
takeaway = add_shape(slide, Inches(0.8), Inches(5.3), Inches(11.7), Inches(1.2), RGBColor(0xFE, 0xF2, 0xF2), ACCENT_RED)
add_text_box(slide, Inches(1.2), Inches(5.5), Inches(11), Inches(0.8),
    "⚠  Most security breaches exploit known vulnerabilities that could have been caught with a proper automated scan.\n"
    "    VulnScan Pro was built to make that scan accessible, intelligent, and actionable.", 13, TEXT_DARK, False)


# ═══════════════════════════════════════════
#   SLIDE 3: WHAT IS VULNSCAN PRO
# ═══════════════════════════════════════════
slide = prs.slides.add_slide(prs.slide_layouts[6])
add_bg(slide, BG_WHITE)
add_accent_bar(slide, Inches(0), Inches(0), prs.slide_width, Inches(0.08), ACCENT_BLUE)

add_text_box(slide, Inches(1), Inches(0.6), Inches(5), Inches(0.4), "OVERVIEW", 13, ACCENT_BLUE, True)
add_text_box(slide, Inches(1), Inches(1.0), Inches(8), Inches(0.6), "What is VulnScan Pro?", 32, TEXT_DARK, True)
add_text_box(slide, Inches(1), Inches(1.7), Inches(10), Inches(0.6),
    "An all-in-one, point-and-shoot web vulnerability scanner that combines network recon, application-layer\n"
    "attack simulation, and infrastructure auditing into a single, actionable security report.", 14, TEXT_MEDIUM, False)

features = [
    ("🕷️", "Smart Crawler", "Maps every page, form, script, and hidden input across the entire site surface with deque-based BFS.", ACCENT_BLUE),
    ("💉", "Multi-Vector SQLi", "Error-based, Time-based Blind, Boolean Blind, and Union-based injection testing across every parameter.", ACCENT_RED),
    ("⚡", "XSS Detection", "32 categorized payloads with context-aware HTML entity verification to eliminate false positives.", ACCENT_ORANGE),
    ("🔍", "DNS Recon", "Record harvesting, subdomain fuzzing, SPF/DKIM/DMARC auditing, reverse DNS, and zone transfer testing.", ACCENT_GREEN),
    ("🔒", "SSL/TLS Analysis", "System-level CA validation matching browser behavior, cipher suite enumeration, and expiry tracking.", ACCENT_PURPLE),
    ("📡", "Full Stack Audit", "Port scanning, tech fingerprinting with CVE lookup, JS secret detection, and security header analysis.", ACCENT_CYAN),
]
for i, (icon, title, desc, color) in enumerate(features):
    row = i // 3
    col = i % 3
    left = Inches(0.8) + Inches(col * 4.1)
    top = Inches(2.7) + Inches(row * 2.1)
    add_icon_card(slide, left, top, Inches(3.8), Inches(1.8), icon, title, desc, color)


# ═══════════════════════════════════════════
#   SLIDE 4: SYSTEM ARCHITECTURE
# ═══════════════════════════════════════════
slide = prs.slides.add_slide(prs.slide_layouts[6])
add_bg(slide, BG_WHITE)
add_accent_bar(slide, Inches(0), Inches(0), prs.slide_width, Inches(0.08), ACCENT_INDIGO)

add_text_box(slide, Inches(1), Inches(0.6), Inches(5), Inches(0.4), "ARCHITECTURE", 13, ACCENT_INDIGO, True)
add_text_box(slide, Inches(1), Inches(1.0), Inches(8), Inches(0.6), "How VulnScan Pro Works", 32, TEXT_DARK, True)

# Pipeline stages
stages = [
    ("1", "URL Input", "User enters target URL\nvia web interface", ACCENT_BLUE),
    ("2", "Crawler", "Maps pages, forms,\nscripts, emails, headers", ACCENT_CYAN),
    ("3", "Parallel Scanners", "XSS, SQLi, DNS, SSL,\nPorts, JS, Headers, Tech", ACCENT_INDIGO),
    ("4", "Score Engine", "Aggregates findings\ninto a security grade", ACCENT_PURPLE),
    ("5", "PDF Report", "Actionable results with\nevidence and severity", ACCENT_GREEN),
]
for i, (num, title, desc, color) in enumerate(stages):
    left = Inches(0.5) + Inches(i * 2.55)
    card = add_shape(slide, left, Inches(2.2), Inches(2.2), Inches(2.0), WHITE, BORDER_LIGHT)
    add_accent_bar(slide, left, Inches(2.2), Inches(2.2), Pt(4), color)
    
    # number circle
    circle = slide.shapes.add_shape(MSO_SHAPE.OVAL, left + Inches(0.75), Inches(2.5), Inches(0.5), Inches(0.5))
    circle.fill.solid()
    circle.fill.fore_color.rgb = color
    circle.line.fill.background()
    tf = circle.text_frame
    tf.paragraphs[0].text = num
    tf.paragraphs[0].font.size = Pt(16)
    tf.paragraphs[0].font.color.rgb = WHITE
    tf.paragraphs[0].font.bold = True
    tf.paragraphs[0].alignment = PP_ALIGN.CENTER
    
    add_text_box(slide, left + Inches(0.2), Inches(3.2), Inches(1.8), Inches(0.4), title, 14, TEXT_DARK, True, PP_ALIGN.CENTER)
    add_text_box(slide, left + Inches(0.15), Inches(3.55), Inches(1.9), Inches(0.6), desc, 10.5, TEXT_MEDIUM, False, PP_ALIGN.CENTER)
    
    # arrow connector
    if i < len(stages) - 1:
        add_text_box(slide, left + Inches(2.2), Inches(2.95), Inches(0.4), Inches(0.4), "→", 22, TEXT_LIGHT, True, PP_ALIGN.CENTER)

# Tech stack bar
tech_bar = add_shape(slide, Inches(0.5), Inches(4.8), Inches(12.3), Inches(1.8), BG_LIGHT_GRAY, BORDER_LIGHT)
add_text_box(slide, Inches(1), Inches(4.95), Inches(3), Inches(0.3), "TECH STACK", 11, TEXT_LIGHT, True)

techs = [
    ("Backend", "Python 3 · Flask · dnspython · cryptography"),
    ("Frontend", "HTML5 · CSS3 · JavaScript · Chart.js"),
    ("Scanning", "requests · BeautifulSoup4 · ssl · socket"),
    ("Testing", "Custom Backtest Framework · 39 automated tests"),
]
for i, (label, detail) in enumerate(techs):
    left = Inches(0.8) + Inches(i * 3.1)
    add_text_box(slide, left, Inches(5.35), Inches(2.8), Inches(0.3), label, 12, ACCENT_INDIGO, True)
    add_text_box(slide, left, Inches(5.65), Inches(2.8), Inches(0.6), detail, 10.5, TEXT_MEDIUM, False)


# ═══════════════════════════════════════════
#   SLIDE 5: CRAWLER INTELLIGENCE
# ═══════════════════════════════════════════
slide = prs.slides.add_slide(prs.slide_layouts[6])
add_bg(slide, BG_WHITE)
add_accent_bar(slide, Inches(0), Inches(0), prs.slide_width, Inches(0.08), ACCENT_CYAN)

add_text_box(slide, Inches(1), Inches(0.6), Inches(5), Inches(0.4), "MODULE DEEP DIVE", 13, ACCENT_CYAN, True)
add_text_box(slide, Inches(1), Inches(1.0), Inches(8), Inches(0.6), "Smart Crawler — The Foundation", 32, TEXT_DARK, True)

# Left: Logic explanation
add_text_box(slide, Inches(1), Inches(1.9), Inches(5.5), Inches(0.3), "What Makes It Smart?", 16, ACCENT_CYAN, True)

points = [
    "✓  URL Normalization — Deduplicates /page/ and /page#section",
    "✓  Deque-based BFS — O(1) queue operations vs O(n) list.pop(0)",
    "✓  Pre-queue Tracking — Prevents duplicates before they enter queue",
    "✓  Rate Limiting — Configurable delay to avoid WAF bans",
    "✓  robots.txt Harvesting — Extracts hidden paths as recon targets",
    "✓  Sensitive Path Probing — Checks /.env, /.git/config, /backup.zip",
    "✓  Inline Script Scanning — Finds hardcoded secrets in <script> tags",
    "✓  Meta Tag Extraction — Identifies frameworks and generators",
]
for i, point in enumerate(points):
    add_text_box(slide, Inches(1.2), Inches(2.35) + Inches(i * 0.42), Inches(5.5), Inches(0.4), point, 12, TEXT_DARK, False)

# Right: Code block
add_code_block(slide, Inches(7.2), Inches(1.9), Inches(5.3), Inches(4.8),
    "# Core Crawling Architecture\n"
    "\n"
    "queue = deque([(start_url, 0)])\n"
    "visited = set()\n"
    "queued = {start_url}  # pre-track\n"
    "\n"
    "while queue:\n"
    "    url, depth = queue.popleft()\n"
    "    if url in visited:\n"
    "        continue\n"
    "    \n"
    "    visited.add(url)\n"
    "    time.sleep(delay)  # rate limit\n"
    "    \n"
    "    response = session.get(url)\n"
    "    soup = parse(response)\n"
    "\n"
    "    extract_forms(soup)\n"
    "    extract_emails(soup)\n"
    "    extract_inline_secrets(soup)\n"
    "    check_security_headers(response)\n"
    "\n"
    "    for link in soup.find_all('a'):\n"
    "        next_url = normalize(link)\n"
    "        if next_url not in queued:\n"
    "            queue.append((next_url, depth+1))\n"
    "            queued.add(next_url)", ACCENT_CYAN)


# ═══════════════════════════════════════════
#   SLIDE 6: XSS DETECTION LOGIC
# ═══════════════════════════════════════════
slide = prs.slides.add_slide(prs.slide_layouts[6])
add_bg(slide, BG_WHITE)
add_accent_bar(slide, Inches(0), Inches(0), prs.slide_width, Inches(0.08), ACCENT_ORANGE)

add_text_box(slide, Inches(1), Inches(0.6), Inches(5), Inches(0.4), "MODULE DEEP DIVE", 13, ACCENT_ORANGE, True)
add_text_box(slide, Inches(1), Inches(1.0), Inches(10), Inches(0.6), "XSS Scanner — Context-Aware Detection", 32, TEXT_DARK, True)

# Comparison: Naive vs Smart
add_text_box(slide, Inches(1), Inches(1.9), Inches(5.5), Inches(0.3), "❌  Naive Detection (How Others Do It)", 14, ACCENT_RED, True)
add_code_block(slide, Inches(1), Inches(2.3), Inches(5.5), Inches(1.6),
    "# BAD: Simple string check\n"
    "if payload in response.text:\n"
    "    flag_as_vulnerable()  # FALSE POSITIVE!\n"
    "\n"
    "# Problem: Website might return the payload\n"
    "# as &lt;script&gt; (HTML-escaped = SAFE)\n"
    "# but this check still flags it as XSS", ACCENT_RED)

add_text_box(slide, Inches(1), Inches(4.15), Inches(5.5), Inches(0.3), "✅  VulnScan Pro Detection (Our Approach)", 14, ACCENT_GREEN, True)
add_code_block(slide, Inches(1), Inches(4.55), Inches(5.5), Inches(2.2),
    "# SMART: Verify HTML chars are UNESCAPED\n"
    "if payload in response.text:\n"
    "    # Check: did < > survive without encoding?\n"
    "    has_raw_lt = '<' in response.text\n"
    "    has_raw_gt = '>' in response.text  \n"
    "    is_not_encoded = '&lt;' not in vicinity\n"
    "    \n"
    "    if has_raw_lt and has_raw_gt and is_not_encoded:\n"
    "        flag_as_vulnerable()  # TRUE POSITIVE ✓\n"
    "\n"
    "# Result: Zero false positives on safe forms", ACCENT_GREEN)

# Right: payload categories
add_text_box(slide, Inches(7.2), Inches(1.9), Inches(5), Inches(0.3), "32 Payloads Across 7 Categories", 14, ACCENT_ORANGE, True)

categories = [
    ("Classic Tags", '<script>alert(1)</script>'),
    ("Event Handlers", '<img src=x onerror=alert(1)>'),
    ("Case Bypass", '<ScRiPt>alert(1)</sCrIpT>'),
    ("Quote Bypass", '<img src=x onerror=alert`1`>'),
    ("JS URI", 'javascript:alert(1)'),
    ("HTML5 Vectors", '<details open ontoggle=alert(1)>'),
    ("Polyglots", "jaVasCript:/*--></title>..."),
]
for i, (cat, example) in enumerate(categories):
    top = Inches(2.4) + Inches(i * 0.6)
    add_shape(slide, Inches(7.2), top, Inches(5.3), Inches(0.5), BG_LIGHT_GRAY, BORDER_LIGHT)
    add_text_box(slide, Inches(7.4), top + Inches(0.05), Inches(1.6), Inches(0.4), cat, 10.5, ACCENT_ORANGE, True)
    add_text_box(slide, Inches(9.1), top + Inches(0.05), Inches(3.2), Inches(0.4), example, 9.5, TEXT_DARK, False, PP_ALIGN.LEFT, FONT_CODE)


# ═══════════════════════════════════════════
#   SLIDE 7: SQL INJECTION — MULTI-VECTOR
# ═══════════════════════════════════════════
slide = prs.slides.add_slide(prs.slide_layouts[6])
add_bg(slide, BG_WHITE)
add_accent_bar(slide, Inches(0), Inches(0), prs.slide_width, Inches(0.08), ACCENT_RED)

add_text_box(slide, Inches(1), Inches(0.6), Inches(5), Inches(0.4), "MODULE DEEP DIVE", 13, ACCENT_RED, True)
add_text_box(slide, Inches(1), Inches(1.0), Inches(10), Inches(0.6), "SQL Injection — Multi-Vector Engine", 32, TEXT_DARK, True)

# 4 technique cards
techniques = [
    ("Error-Based", "Triggers database errors by\ninjecting malformed SQL.\nDetects MySQL, PostgreSQL,\nMSSQL, Oracle & SQLite\nerror signatures.", 
     "' OR '1'='1\n'; SELECT 1/0--", ACCENT_RED),
    ("Union-Based", "Appends UNION SELECT to\nmerge attacker-controlled\ndata with the original\nquery results.", 
     "' UNION SELECT null,null--\n' UNION ALL SELECT 'test'--", ACCENT_ORANGE),
    ("Time-Based Blind", "Injects sleep commands.\nIf response takes exactly\n6 seconds instead of 100ms,\nthe database executed\nour payload.", 
     "1' AND SLEEP(6)-- -\n1'; SELECT pg_sleep(6)-- -", ACCENT_PURPLE),
    ("Boolean Blind", "Sends TRUE (1=1) and\nFALSE (1=2) conditions.\nIf response length differs\nby >50 chars, database\nis responding to logic.", 
     "1' AND '1'='1  → 2847 bytes\n1' AND '1'='2  → 2104 bytes", ACCENT_BLUE),
]
for i, (title, desc, code, color) in enumerate(techniques):
    left = Inches(0.5) + Inches(i * 3.15)
    card = add_shape(slide, left, Inches(2.0), Inches(2.9), Inches(4.8), WHITE, BORDER_LIGHT)
    add_accent_bar(slide, left, Inches(2.0), Inches(2.9), Pt(4), color)
    add_text_box(slide, left + Inches(0.25), Inches(2.3), Inches(2.4), Inches(0.4), title, 15, color, True)
    add_text_box(slide, left + Inches(0.25), Inches(2.8), Inches(2.4), Inches(2.0), desc, 11, TEXT_MEDIUM, False)
    add_code_block(slide, left + Inches(0.15), Inches(5.0), Inches(2.6), Inches(1.5), code, color)


# ═══════════════════════════════════════════
#   SLIDE 8: BLIND SQLi DEEP DIVE
# ═══════════════════════════════════════════
slide = prs.slides.add_slide(prs.slide_layouts[6])
add_bg(slide, BG_WHITE)
add_accent_bar(slide, Inches(0), Inches(0), prs.slide_width, Inches(0.08), ACCENT_PURPLE)

add_text_box(slide, Inches(1), Inches(0.6), Inches(5), Inches(0.4), "LOGIC DEEP DIVE", 13, ACCENT_PURPLE, True)
add_text_box(slide, Inches(1), Inches(1.0), Inches(10), Inches(0.6), "How Blind SQLi Detection Actually Works", 32, TEXT_DARK, True)
add_text_box(slide, Inches(1), Inches(1.7), Inches(10), Inches(0.5),
    "When a web application hides all database errors (which most production apps do), traditional error-based\n"
    "scanning becomes useless. Our engine uses mathematical inference to detect injection without any error messages.", 13, TEXT_MEDIUM, False)

# Time-based flow
add_text_box(slide, Inches(1), Inches(2.6), Inches(5.5), Inches(0.3), "⏱️  Time-Based Inference", 16, ACCENT_PURPLE, True)
add_code_block(slide, Inches(1), Inches(3.0), Inches(5.5), Inches(3.8),
    "# Step 1: Inject a SLEEP command\n"
    "payload = \"1' AND SLEEP(6)-- -\"\n"
    "data[param] = payload\n"
    "\n"
    "# Step 2: Measure response time\n"
    "start = time.time()\n"
    "response = requests.post(url, data=data)\n"
    "elapsed = time.time() - start\n"
    "\n"
    "# Step 3: Check threshold\n"
    "if elapsed >= 5.5:  # 6s sleep - 0.5 network\n"
    "    # ⚠ DATABASE EXECUTED OUR COMMAND\n"
    "    # Normal request: ~0.1 seconds\n"
    "    # Our request:    ~6.0 seconds\n"
    "    # Verdict: VULNERABLE ✓\n"
    "    flag_sqli('Blind Time-Based')", ACCENT_PURPLE)

# Boolean flow
add_text_box(slide, Inches(7.2), Inches(2.6), Inches(5.5), Inches(0.3), "⚖️  Boolean-Based Inference", 16, ACCENT_BLUE, True)
add_code_block(slide, Inches(7.2), Inches(3.0), Inches(5.3), Inches(3.8),
    "# Step 1: Send a TRUE condition\n"
    "data[param] = \"1' AND '1'='1\"  # TRUE\n"
    "res_true = requests.post(url, data)\n"
    "# Response: 2847 bytes (full page)\n"
    "\n"
    "# Step 2: Send a FALSE condition  \n"
    "data[param] = \"1' AND '1'='2\"  # FALSE\n"
    "res_false = requests.post(url, data)\n"
    "# Response: 2104 bytes (empty/diff)\n"
    "\n"
    "# Step 3: Calculate difference\n"
    "diff = abs(len(res_true) - len(res_false))\n"
    "# diff = 743 bytes (> 50 threshold)\n"
    "\n"
    "# Verdict: Database is responding to\n"
    "# our boolean logic = VULNERABLE ✓\n"
    "flag_sqli('Boolean Blind')", ACCENT_BLUE)


# ═══════════════════════════════════════════
#   SLIDE 9: DNS RECON
# ═══════════════════════════════════════════
slide = prs.slides.add_slide(prs.slide_layouts[6])
add_bg(slide, BG_WHITE)
add_accent_bar(slide, Inches(0), Inches(0), prs.slide_width, Inches(0.08), ACCENT_GREEN)

add_text_box(slide, Inches(1), Inches(0.6), Inches(5), Inches(0.4), "MODULE DEEP DIVE", 13, ACCENT_GREEN, True)
add_text_box(slide, Inches(1), Inches(1.0), Inches(10), Inches(0.6), "DNS Recon — Infrastructure Intelligence", 32, TEXT_DARK, True)

# Left: What it does
features_dns = [
    ("Record Harvesting", "A, AAAA, MX, NS, TXT, CNAME, SOA, CAA, SRV — with TTL tracking for each record"),
    ("Reverse DNS (PTR)", "Takes discovered IPs and performs reverse lookups to reveal shared hosting or CDN providers"),
    ("Subdomain Fuzzing", "Brute-forces 22 common prefixes (admin, dev, staging, api, vpn) to find hidden portals"),
    ("Email Security Audit", "Analyzes SPF for +all/~all misconfigurations, probes 9 DKIM selectors, validates DMARC"),
    ("Zone Transfer Test", "Attempts AXFR against all NS servers to check if the entire DNS zone is exposed"),
    ("MX Resolution", "Resolves mail server hostnames to their physical IP addresses for mail infrastructure mapping"),
]
for i, (title, desc) in enumerate(features_dns):
    top = Inches(2.0) + Inches(i * 0.82)
    add_shape(slide, Inches(1), top, Inches(6), Inches(0.7), WHITE, BORDER_LIGHT)
    add_accent_bar(slide, Inches(1), top, Pt(4), Inches(0.7), ACCENT_GREEN)
    add_text_box(slide, Inches(1.3), top + Inches(0.05), Inches(1.8), Inches(0.3), title, 11.5, ACCENT_GREEN, True)
    add_text_box(slide, Inches(1.3), top + Inches(0.32), Inches(5.5), Inches(0.35), desc, 10, TEXT_MEDIUM, False)

# Right: code
add_code_block(slide, Inches(7.5), Inches(2.0), Inches(5), Inches(4.8),
    "# SPF Weakness Analysis\n"
    "def analyze_spf(spf_record):\n"
    "    issues = []\n"
    "    if '+all' in spf_record:\n"
    "        issues.append('CRITICAL: Anyone \n"
    "            can spoof this domain')\n"
    "    if '~all' in spf_record:\n"
    "        issues.append('WARN: Softfail\n"
    "            is not enforced')\n"
    "    if '-all' not in spf_record:\n"
    "        issues.append('INFO: No strict\n"
    "            rejection set')\n"
    "\n"
    "# Subdomain Enumeration\n"
    "SUBS = ['www', 'mail', 'admin',\n"
    "        'api', 'dev', 'staging',\n"
    "        'vpn', 'cdn', 'beta']\n"
    "\n"
    "for sub in SUBS:\n"
    "    target = f'{sub}.{domain}'\n"
    "    ips = resolver.resolve(target, 'A')\n"
    "    if ips:\n"
    "        found.append(target)", ACCENT_GREEN)


# ═══════════════════════════════════════════
#   SLIDE 10: PARAMETER ISOLATION LOGIC
# ═══════════════════════════════════════════
slide = prs.slides.add_slide(prs.slide_layouts[6])
add_bg(slide, BG_WHITE)
add_accent_bar(slide, Inches(0), Inches(0), prs.slide_width, Inches(0.08), ACCENT_INDIGO)

add_text_box(slide, Inches(1), Inches(0.6), Inches(5), Inches(0.4), "LOGIC DEEP DIVE", 13, ACCENT_INDIGO, True)
add_text_box(slide, Inches(1), Inches(1.0), Inches(10), Inches(0.6), "Per-Parameter Isolation Testing", 32, TEXT_DARK, True)
add_text_box(slide, Inches(1), Inches(1.7), Inches(10), Inches(0.5),
    "Both the XSS and SQLi scanners isolate each parameter individually. When testing one field,\n"
    "all other fields are filled with safe mock data — pinpointing exactly which input is vulnerable.", 13, TEXT_MEDIUM, False)

# Visual: Form with highlighted params
add_text_box(slide, Inches(1), Inches(2.6), Inches(5.5), Inches(0.3), "Example: Login Form with 3 Parameters", 14, ACCENT_INDIGO, True)

iterations = [
    ("Iteration 1", "username", "' OR '1'='1", "password", "test", "remember", "test", ACCENT_RED),
    ("Iteration 2", "username", "test", "password", "' OR '1'='1", "remember", "test", ACCENT_ORANGE),
    ("Iteration 3", "username", "test", "password", "test", "remember", "' OR '1'='1", ACCENT_PURPLE),
]
for i, (iter_label, p1_name, p1_val, p2_name, p2_val, p3_name, p3_val, color) in enumerate(iterations):
    top = Inches(3.1) + Inches(i * 1.25)
    add_shape(slide, Inches(1), top, Inches(5.5), Inches(1.05), WHITE, BORDER_LIGHT)
    add_accent_bar(slide, Inches(1), top, Inches(5.5), Pt(3), color)
    add_text_box(slide, Inches(1.2), top + Inches(0.08), Inches(1.5), Inches(0.3), iter_label, 12, color, True)
    
    fields = [(p1_name, p1_val), (p2_name, p2_val), (p3_name, p3_val)]
    for j, (name, val) in enumerate(fields):
        left = Inches(1.2) + Inches(j * 1.8)
        is_payload = "OR" in val or "'" in val
        fc = ACCENT_RED if is_payload else TEXT_LIGHT
        add_text_box(slide, left, top + Inches(0.35), Inches(1.6), Inches(0.25), name + ":", 10, TEXT_LIGHT, True)
        add_text_box(slide, left, top + Inches(0.58), Inches(1.6), Inches(0.35), val, 10, fc, is_payload, PP_ALIGN.LEFT, FONT_CODE if is_payload else FONT_BODY)

# Right side explanation
add_text_box(slide, Inches(7.2), Inches(2.6), Inches(5), Inches(0.3), "Why This Matters", 14, ACCENT_INDIGO, True)
add_code_block(slide, Inches(7.2), Inches(3.0), Inches(5.3), Inches(3.6),
    "# Per-Param Testing Logic\n"
    "for inp in form.inputs:\n"
    "    if inp.name in already_vulnerable:\n"
    "        continue  # skip if found\n"
    "\n"
    "    for payload in PAYLOADS:\n"
    "        data = {}\n"
    "        for other in form.inputs:\n"
    "            if other.name == inp.name:\n"
    "                data[other.name] = payload\n"
    "            else:\n"
    "                data[other.name] = 'test'\n"
    "\n"
    "        response = send(data)\n"
    "        if is_vulnerable(response):\n"
    "            report(inp.name, payload)\n"
    "            break  # next PARAM, not form", ACCENT_INDIGO)


# ═══════════════════════════════════════════
#   SLIDE 11: BACKTEST RESULTS
# ═══════════════════════════════════════════
slide = prs.slides.add_slide(prs.slide_layouts[6])
add_bg(slide, BG_WHITE)
add_accent_bar(slide, Inches(0), Inches(0), prs.slide_width, Inches(0.08), ACCENT_GREEN)

add_text_box(slide, Inches(1), Inches(0.6), Inches(5), Inches(0.4), "VALIDATION", 13, ACCENT_GREEN, True)
add_text_box(slide, Inches(1), Inches(1.0), Inches(10), Inches(0.6), "Backtest Results — 100% Accuracy", 32, TEXT_DARK, True)
add_text_box(slide, Inches(1), Inches(1.7), Inches(10), Inches(0.4),
    "Every module was tested against a deliberately vulnerable Flask test server with known True Positives and True Negatives.", 13, TEXT_MEDIUM, False)

# Results table
modules = [
    ("Header Scanner",      "9",  "9", "0", "100%", ACCENT_GREEN),
    ("XSS Scanner",         "2",  "2", "0", "100%", ACCENT_GREEN),
    ("SQLi Scanner",        "2",  "2", "0", "100%", ACCENT_GREEN),
    ("Crawler",             "6",  "6", "0", "100%", ACCENT_GREEN),
    ("Tech Fingerprint",    "5",  "5", "0", "100%", ACCENT_GREEN),
    ("JS Analyzer",         "7",  "7", "0", "100%", ACCENT_GREEN),
    ("Port Scanner",        "1",  "1", "0", "100%", ACCENT_GREEN),
    ("DNS Recon",           "4",  "4", "0", "100%", ACCENT_GREEN),
    ("SSL Scanner",         "4",  "4", "0", "100%", ACCENT_GREEN),
]

# Header row
header_top = Inches(2.4)
add_shape(slide, Inches(1.5), header_top, Inches(10), Inches(0.45), ACCENT_BLUE)
headers = [("Module", 3.5), ("Tests", 1.2), ("Pass", 1.2), ("Fail", 1.2), ("Accuracy", 1.5)]
left = Inches(1.7)
for hdr, w in headers:
    add_text_box(slide, left, header_top + Inches(0.07), Inches(w), Inches(0.35), hdr, 12, WHITE, True, PP_ALIGN.CENTER)
    left += Inches(w + 0.15)

for i, (module, tests, passed, failed, accuracy, color) in enumerate(modules):
    row_top = Inches(2.9) + Inches(i * 0.42)
    bg = BG_LIGHT_GRAY if i % 2 == 0 else WHITE
    add_shape(slide, Inches(1.5), row_top, Inches(10), Inches(0.4), bg)
    
    vals = [(module, 3.5), (tests, 1.2), (passed, 1.2), (failed, 1.2), (accuracy, 1.5)]
    left = Inches(1.7)
    for j, (val, w) in enumerate(vals):
        c = ACCENT_GREEN if j == 4 else TEXT_DARK
        b = j == 4
        add_text_box(slide, left, row_top + Inches(0.05), Inches(w), Inches(0.3), val, 11, c, b, PP_ALIGN.CENTER if j > 0 else PP_ALIGN.LEFT)
        left += Inches(w + 0.15)

# Total bar
total_top = Inches(2.9) + Inches(len(modules) * 0.42) + Inches(0.15)
add_shape(slide, Inches(1.5), total_top, Inches(10), Inches(0.5), RGBColor(0xEC, 0xFD, 0xF5), ACCENT_GREEN)
total_vals = [("TOTAL", 3.5), ("39", 1.2), ("39", 1.2), ("0", 1.2), ("100%", 1.5)]
left = Inches(1.7)
for j, (val, w) in enumerate(total_vals):
    add_text_box(slide, left, total_top + Inches(0.08), Inches(w), Inches(0.35), val, 13, ACCENT_GREEN if j == 4 else TEXT_DARK, True, PP_ALIGN.CENTER if j > 0 else PP_ALIGN.LEFT)
    left += Inches(w + 0.15)


# ═══════════════════════════════════════════
#   SLIDE 12: COMPETITIVE LANDSCAPE
# ═══════════════════════════════════════════
slide = prs.slides.add_slide(prs.slide_layouts[6])
add_bg(slide, BG_WHITE)
add_accent_bar(slide, Inches(0), Inches(0), prs.slide_width, Inches(0.08), ACCENT_INDIGO)

add_text_box(slide, Inches(1), Inches(0.6), Inches(5), Inches(0.4), "MARKET POSITIONING", 13, ACCENT_INDIGO, True)
add_text_box(slide, Inches(1), Inches(1.0), Inches(10), Inches(0.6), "How VulnScan Pro Compares", 32, TEXT_DARK, True)

# Comparison table
comp_header_top = Inches(2.0)
add_shape(slide, Inches(0.8), comp_header_top, Inches(11.7), Inches(0.5), ACCENT_INDIGO)
comp_headers = [("Feature", 2.8), ("VulnScan Pro", 1.8), ("OWASP ZAP", 1.5), ("Nessus", 1.3), ("Burp Suite", 1.5), ("Nikto", 1.2)]
left = Inches(1)
for hdr, w in comp_headers:
    add_text_box(slide, left, comp_header_top + Inches(0.08), Inches(w), Inches(0.35), hdr, 11, WHITE, True, PP_ALIGN.CENTER)
    left += Inches(w + 0.1)

comp_rows = [
    ("One-Click Scanning",      "✅", "❌", "✅", "❌", "✅"),
    ("Blind SQLi Detection",    "✅", "✅", "✅", "✅", "❌"),
    ("DNS Recon + Subdomain",   "✅", "❌", "✅", "❌", "❌"),
    ("JS Secret Detection",     "✅", "⚠️", "❌", "✅", "❌"),
    ("SSL Certificate Audit",   "✅", "❌", "✅", "❌", "❌"),
    ("Free & Open Source",      "✅", "✅", "❌", "❌", "✅"),
    ("Modern Web UI",           "✅", "⚠️", "✅", "✅", "❌"),
    ("No Java Dependency",      "✅", "❌", "❌", "❌", "✅"),
    ("PDF Report Generation",   "✅", "✅", "✅", "✅", "❌"),
]
for i, row in enumerate(comp_rows):
    row_top = Inches(2.55) + Inches(i * 0.42)
    bg = BG_LIGHT_GRAY if i % 2 == 0 else WHITE
    add_shape(slide, Inches(0.8), row_top, Inches(11.7), Inches(0.4), bg)
    
    left = Inches(1)
    widths = [2.8, 1.8, 1.5, 1.3, 1.5, 1.2]
    for j, (val, w) in enumerate(zip(row, widths)):
        align = PP_ALIGN.LEFT if j == 0 else PP_ALIGN.CENTER
        c = ACCENT_GREEN if val == "✅" else (ACCENT_RED if val == "❌" else TEXT_DARK)
        add_text_box(slide, left, row_top + Inches(0.05), Inches(w), Inches(0.3), val, 11, c, j==0, align)
        left += Inches(w + 0.1)


# ═══════════════════════════════════════════
#   SLIDE 13: FUTURE SCOPE
# ═══════════════════════════════════════════
slide = prs.slides.add_slide(prs.slide_layouts[6])
add_bg(slide, BG_WHITE)
add_accent_bar(slide, Inches(0), Inches(0), prs.slide_width, Inches(0.08), ACCENT_PURPLE)

add_text_box(slide, Inches(1), Inches(0.6), Inches(5), Inches(0.4), "ROADMAP", 13, ACCENT_PURPLE, True)
add_text_box(slide, Inches(1), Inches(1.0), Inches(10), Inches(0.6), "Future Scope & Enhancements", 32, TEXT_DARK, True)

future_items = [
    ("🔐", "Authenticated Scanning", "Auto-login with session cookies to scan pages behind authentication walls (dashboards, admin panels).", ACCENT_BLUE),
    ("🌐", "Headless Browser Integration", "Playwright/Selenium integration to render JavaScript SPAs (React, Angular, Vue) before crawling the virtual DOM.", ACCENT_CYAN),
    ("🛡️", "WAF Evasion Engine", "Request manager with User-Agent rotation, payload obfuscation, rate-limit backoff, and proxy pool support.", ACCENT_RED),
    ("💻", "Command Injection & LFI", "Expand vulnerability coverage to OS command injection, path traversal, SSRF, and IDOR testing.", ACCENT_ORANGE),
    ("🔄", "CI/CD Integration", "GitHub Actions / Jenkins plugin for automated security scanning on every deployment pipeline.", ACCENT_GREEN),
    ("📊", "Historical Trend Dashboard", "Track vulnerability scores over time to measure security posture improvement across releases.", ACCENT_PURPLE),
]
for i, (icon, title, desc, color) in enumerate(future_items):
    row = i // 3
    col = i % 3
    left = Inches(0.8) + Inches(col * 4.1)
    top = Inches(2.0) + Inches(row * 2.4)
    add_icon_card(slide, left, top, Inches(3.8), Inches(2.1), icon, title, desc, color)


# ═══════════════════════════════════════════
#   SLIDE 14: THANK YOU
# ═══════════════════════════════════════════
slide = prs.slides.add_slide(prs.slide_layouts[6])
add_bg(slide, BG_WHITE)
add_accent_bar(slide, Inches(0), Inches(0), prs.slide_width, Inches(0.08), ACCENT_BLUE)

add_text_box(slide, Inches(1), Inches(2.0), Inches(11), Inches(0.5), "🛡️  VULNSCAN PRO", 16, ACCENT_BLUE, True, PP_ALIGN.CENTER)
add_text_box(slide, Inches(1), Inches(2.7), Inches(11), Inches(1.0), "Thank You", 48, TEXT_DARK, True, PP_ALIGN.CENTER)
add_text_box(slide, Inches(2), Inches(3.8), Inches(9), Inches(0.5),
    "Questions & Discussion", 18, TEXT_MEDIUM, False, PP_ALIGN.CENTER)

# Bottom metric recap
metrics = [
    ("9 Modules", "Full-stack coverage"),
    ("39 Tests", "100% backtest accuracy"),
    ("32+ Payloads", "XSS detection library"),
    ("6 Techniques", "SQLi attack vectors"),
]
for i, (val, label) in enumerate(metrics):
    left = Inches(1.8) + Inches(i * 2.6)
    card = add_shape(slide, left, Inches(5.0), Inches(2.2), Inches(1.2), WHITE, BORDER_LIGHT)
    add_text_box(slide, left + Inches(0.3), Inches(5.15), Inches(1.6), Inches(0.5), val, 18, ACCENT_BLUE, True, PP_ALIGN.CENTER)
    add_text_box(slide, left + Inches(0.3), Inches(5.6), Inches(1.6), Inches(0.4), label, 11, TEXT_MEDIUM, False, PP_ALIGN.CENTER)


# ═══════════════════════════════════════════
#   SAVE
# ═══════════════════════════════════════════
output_path = os.path.join(os.path.dirname(__file__), "VulnScan_Pro_Presentation.pptx")
prs.save(output_path)
print(f"✅ Presentation saved to: {output_path}")
print(f"   Total slides: {len(prs.slides)}")
