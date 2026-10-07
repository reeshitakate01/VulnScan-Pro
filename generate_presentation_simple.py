from pptx import Presentation
from pptx.util import Inches, Pt
from pptx.dml.color import RGBColor
from pptx.enum.text import PP_ALIGN
from pptx.enum.shapes import MSO_SHAPE
import os

prs = Presentation()
prs.slide_width = Inches(13.333)
prs.slide_height = Inches(7.5)

# ═══════════════════════════════════════════
#   CLEAN COLOR PALETTE
# ═══════════════════════════════════════════
BG         = RGBColor(0xFF, 0xFF, 0xFF)
BG_SOFT    = RGBColor(0xF8, 0xFA, 0xFC)
DARK       = RGBColor(0x1E, 0x29, 0x3B)
MEDIUM     = RGBColor(0x64, 0x74, 0x8B)
LIGHT      = RGBColor(0x94, 0xA3, 0xB8)
BLUE       = RGBColor(0x37, 0x30, 0xA3)
SKY        = RGBColor(0x38, 0xBD, 0xF8)
GREEN      = RGBColor(0x22, 0xC5, 0x5E)
RED        = RGBColor(0xEF, 0x44, 0x44)
ORANGE     = RGBColor(0xF9, 0x73, 0x16)
PURPLE     = RGBColor(0xA7, 0x55, 0xF7)
WHITE      = RGBColor(0xFF, 0xFF, 0xFF)
BORDER     = RGBColor(0xE2, 0xE8, 0xF0)
FONT       = "Segoe UI"

def bg(slide):
    slide.background.fill.solid()
    slide.background.fill.fore_color.rgb = BG

def bar(slide, l, t, w, h, c):
    s = slide.shapes.add_shape(MSO_SHAPE.RECTANGLE, l, t, w, h)
    s.fill.solid(); s.fill.fore_color.rgb = c; s.line.fill.background()
    return s

def box(slide, l, t, w, h, fc, bc=None):
    s = slide.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, l, t, w, h)
    s.fill.solid(); s.fill.fore_color.rgb = fc
    if bc: s.line.color.rgb = bc; s.line.width = Pt(1)
    else: s.line.fill.background()
    return s

def txt(slide, l, t, w, h, text, sz=14, c=DARK, b=False, al=PP_ALIGN.LEFT):
    tb = slide.shapes.add_textbox(l, t, w, h)
    tf = tb.text_frame; tf.word_wrap = True
    p = tf.paragraphs[0]; p.text = text
    p.font.size = Pt(sz); p.font.color.rgb = c; p.font.bold = b; p.font.name = FONT; p.alignment = al
    return tb

def card(slide, l, t, w, h, accent, icon, title, body):
    box(slide, l, t, w, h, WHITE, BORDER)
    bar(slide, l, t, w, Pt(4), accent)
    txt(slide, l+Inches(0.3), t+Inches(0.25), w-Inches(0.6), Inches(0.5), icon, 24, accent, True, PP_ALIGN.CENTER)
    txt(slide, l+Inches(0.2), t+Inches(0.8), w-Inches(0.4), Inches(0.4), title, 15, DARK, True, PP_ALIGN.CENTER)
    txt(slide, l+Inches(0.2), t+Inches(1.25), w-Inches(0.4), h-Inches(1.5), body, 11, MEDIUM, False, PP_ALIGN.CENTER)


# ═══════════════════════════════════════════
#   SLIDE 1 — TITLE
# ═══════════════════════════════════════════
s = prs.slides.add_slide(prs.slide_layouts[6]); bg(s)
bar(s, Inches(0), Inches(0), prs.slide_width, Inches(0.06), BLUE)
txt(s, Inches(1.5), Inches(2.0), Inches(10), Inches(0.5), "VULNSCAN PRO", 18, BLUE, True, PP_ALIGN.CENTER)
txt(s, Inches(1.5), Inches(2.7), Inches(10), Inches(1.2), "Intelligent Web\nVulnerability Scanner", 48, DARK, True, PP_ALIGN.CENTER)
txt(s, Inches(2.5), Inches(4.3), Inches(8), Inches(0.6), "Point. Scan. Protect.\nA single tool that finds security flaws before hackers do.", 16, MEDIUM, False, PP_ALIGN.CENTER)

# 4 stat pills
for i, (v, l) in enumerate([("9", "Modules"), ("100%", "Accuracy"), ("32+", "XSS Payloads"), ("6", "SQLi Methods")]):
    left = Inches(2.2) + Inches(i * 2.4)
    box(s, left, Inches(5.3), Inches(2), Inches(1.0), BG_SOFT, BORDER)
    txt(s, left, Inches(5.4), Inches(2), Inches(0.45), v, 24, BLUE, True, PP_ALIGN.CENTER)
    txt(s, left, Inches(5.85), Inches(2), Inches(0.3), l, 11, MEDIUM, False, PP_ALIGN.CENTER)


# ═══════════════════════════════════════════
#   SLIDE 2 — THE PROBLEM (Simple)
# ═══════════════════════════════════════════
s = prs.slides.add_slide(prs.slide_layouts[6]); bg(s)
bar(s, Inches(0), Inches(0), prs.slide_width, Inches(0.06), RED)
txt(s, Inches(1), Inches(0.5), Inches(5), Inches(0.4), "WHY THIS MATTERS", 13, RED, True)
txt(s, Inches(1), Inches(1.0), Inches(10), Inches(0.8), "Websites Get Hacked Every Day", 36, DARK, True)

problems = [
    ("$4.45 Million", "Average cost of a single\ndata breach", RED),
    ("43%", "Of all cyberattacks\ntarget small businesses", ORANGE),
    ("74%", "Of web apps have at least\none critical vulnerability", PURPLE),
]
for i, (v, d, c) in enumerate(problems):
    left = Inches(1) + Inches(i * 3.8)
    box(s, left, Inches(2.4), Inches(3.5), Inches(2.2), WHITE, BORDER)
    bar(s, left, Inches(2.4), Inches(3.5), Pt(5), c)
    txt(s, left+Inches(0.3), Inches(2.8), Inches(2.9), Inches(0.6), v, 36, c, True, PP_ALIGN.CENTER)
    txt(s, left+Inches(0.3), Inches(3.5), Inches(2.9), Inches(0.8), d, 14, MEDIUM, False, PP_ALIGN.CENTER)

# Bottom banner
box(s, Inches(1), Inches(5.2), Inches(11.3), Inches(1.3), RGBColor(0xFE, 0xF2, 0xF2), RED)
txt(s, Inches(1.5), Inches(5.5), Inches(10.5), Inches(0.8),
    "Most breaches exploit known vulnerabilities that a proper scan would have caught.\n"
    "VulnScan Pro makes that scan simple, fast, and intelligent.", 15, DARK, False, PP_ALIGN.CENTER)


# ═══════════════════════════════════════════
#   SLIDE 3 — WHAT IT DOES (Simple Overview)
# ═══════════════════════════════════════════
s = prs.slides.add_slide(prs.slide_layouts[6]); bg(s)
bar(s, Inches(0), Inches(0), prs.slide_width, Inches(0.06), BLUE)
txt(s, Inches(1), Inches(0.5), Inches(5), Inches(0.4), "OVERVIEW", 13, BLUE, True)
txt(s, Inches(1), Inches(1.0), Inches(10), Inches(0.6), "What Does VulnScan Pro Do?", 36, DARK, True)
txt(s, Inches(1), Inches(1.8), Inches(10), Inches(0.5),
    "You give it a website URL. It automatically finds every page, tests every form,\n"
    "checks every configuration, and tells you exactly what's broken — in one click.", 15, MEDIUM, False)

modules = [
    ("🕷️", "Crawler", "Maps every page\nand form on the site", SKY),
    ("💉", "SQL Injection", "Tests if hackers can\nsteal your database", RED),
    ("⚡", "XSS Scanner", "Tests if hackers can\ninject malicious scripts", ORANGE),
    ("🔍", "DNS Recon", "Finds hidden subdomains\nand email weaknesses", GREEN),
    ("🔒", "SSL Checker", "Verifies your HTTPS\ncertificate is valid", PURPLE),
    ("📡", "Full Audit", "Ports, headers, tech\nstack, and JS secrets", BLUE),
]
for i, (icon, title, body, color) in enumerate(modules):
    col = i % 3; row = i // 3
    left = Inches(1) + Inches(col * 3.9)
    top = Inches(2.8) + Inches(row * 2.1)
    card(s, left, top, Inches(3.5), Inches(1.8), color, icon, title, body)


# ═══════════════════════════════════════════
#   SLIDE 4 — HOW IT WORKS (Pipeline)
# ═══════════════════════════════════════════
s = prs.slides.add_slide(prs.slide_layouts[6]); bg(s)
bar(s, Inches(0), Inches(0), prs.slide_width, Inches(0.06), BLUE)
txt(s, Inches(1), Inches(0.5), Inches(5), Inches(0.4), "HOW IT WORKS", 13, BLUE, True)
txt(s, Inches(1), Inches(1.0), Inches(10), Inches(0.6), "Simple 5-Step Process", 36, DARK, True)

steps = [
    ("1", "Enter URL", "Type the website\naddress you want\nto test", SKY),
    ("2", "Auto Crawl", "The crawler maps\nevery page, form,\nand script file", GREEN),
    ("3", "Run Scans", "9 scanners test for\nXSS, SQLi, SSL,\nDNS & more", ORANGE),
    ("4", "Get Score", "Findings are graded\ninto a simple\nsecurity score", PURPLE),
    ("5", "Download Report", "A detailed PDF with\nevidence and\nfix suggestions", BLUE),
]
for i, (num, title, desc, color) in enumerate(steps):
    left = Inches(0.7) + Inches(i * 2.55)
    box(s, left, Inches(2.2), Inches(2.2), Inches(3.0), WHITE, BORDER)
    bar(s, left, Inches(2.2), Inches(2.2), Pt(5), color)
    
    circle = s.shapes.add_shape(MSO_SHAPE.OVAL, left+Inches(0.75), Inches(2.6), Inches(0.6), Inches(0.6))
    circle.fill.solid(); circle.fill.fore_color.rgb = color; circle.line.fill.background()
    tf = circle.text_frame; tf.paragraphs[0].text = num
    tf.paragraphs[0].font.size = Pt(20); tf.paragraphs[0].font.color.rgb = WHITE
    tf.paragraphs[0].font.bold = True; tf.paragraphs[0].alignment = PP_ALIGN.CENTER
    
    txt(s, left+Inches(0.1), Inches(3.4), Inches(2), Inches(0.4), title, 16, DARK, True, PP_ALIGN.CENTER)
    txt(s, left+Inches(0.1), Inches(3.85), Inches(2), Inches(1.0), desc, 12, MEDIUM, False, PP_ALIGN.CENTER)
    
    if i < 4:
        txt(s, left+Inches(2.15), Inches(3.3), Inches(0.5), Inches(0.5), "→", 28, LIGHT, True, PP_ALIGN.CENTER)

# Tech bar
box(s, Inches(0.7), Inches(5.7), Inches(11.9), Inches(1.0), BG_SOFT, BORDER)
txt(s, Inches(1.2), Inches(5.85), Inches(11), Inches(0.6),
    "Built with:   Python  ·  Flask  ·  BeautifulSoup  ·  dnspython  ·  HTML/CSS/JS  ·  Chart.js", 13, MEDIUM, False, PP_ALIGN.CENTER)


# ═══════════════════════════════════════════
#   SLIDE 5 — XSS EXPLAINED SIMPLY
# ═══════════════════════════════════════════
s = prs.slides.add_slide(prs.slide_layouts[6]); bg(s)
bar(s, Inches(0), Inches(0), prs.slide_width, Inches(0.06), ORANGE)
txt(s, Inches(1), Inches(0.5), Inches(5), Inches(0.4), "KEY FEATURE", 13, ORANGE, True)
txt(s, Inches(1), Inches(1.0), Inches(10), Inches(0.6), "How We Detect XSS (Cross-Site Scripting)", 36, DARK, True)

# Left: What is XSS
box(s, Inches(1), Inches(2.0), Inches(5.5), Inches(4.5), BG_SOFT, BORDER)
txt(s, Inches(1.4), Inches(2.2), Inches(4.7), Inches(0.4), "What is XSS?", 18, ORANGE, True)
txt(s, Inches(1.4), Inches(2.8), Inches(4.7), Inches(1.2),
    "Imagine a search bar on a website.\n"
    "You type a search term, and the website\n"
    "shows it back to you on the page.\n\n"
    "But what if instead of a search term, you\n"
    "type a piece of JavaScript code?", 14, DARK, False)
txt(s, Inches(1.4), Inches(4.3), Inches(4.7), Inches(0.8),
    "If the website displays that code without\n"
    "cleaning it first, the code RUNS in every\n"
    "visitor's browser — stealing their cookies,\n"
    "passwords, and session data.", 13, RED, False)

# Right: Our approach
box(s, Inches(7), Inches(2.0), Inches(5.5), Inches(4.5), WHITE, BORDER)
bar(s, Inches(7), Inches(2.0), Inches(5.5), Pt(5), GREEN)
txt(s, Inches(7.4), Inches(2.3), Inches(4.7), Inches(0.4), "Our Smart Detection", 18, GREEN, True)

checks = [
    ("✅  32 different attack payloads", "We test classic tags, event handlers,\ncase tricks, encoding bypasses, and more"),
    ("✅  Context-aware verification", "We check if dangerous characters like < >\nsurvived without being escaped"),
    ("✅  Zero false positives", "If the website safely encodes the input,\nwe do NOT flag it — unlike basic scanners"),
]
top = Inches(2.9)
for title, desc in checks:
    txt(s, Inches(7.4), top, Inches(4.7), Inches(0.35), title, 13, DARK, True)
    txt(s, Inches(7.7), top + Inches(0.35), Inches(4.4), Inches(0.55), desc, 11, MEDIUM, False)
    top += Inches(1.05)


# ═══════════════════════════════════════════
#   SLIDE 6 — SQL INJECTION EXPLAINED SIMPLY
# ═══════════════════════════════════════════
s = prs.slides.add_slide(prs.slide_layouts[6]); bg(s)
bar(s, Inches(0), Inches(0), prs.slide_width, Inches(0.06), RED)
txt(s, Inches(1), Inches(0.5), Inches(5), Inches(0.4), "KEY FEATURE", 13, RED, True)
txt(s, Inches(1), Inches(1.0), Inches(10), Inches(0.6), "How We Detect SQL Injection", 36, DARK, True)

# What is SQLi
box(s, Inches(1), Inches(2.0), Inches(5.5), Inches(2.0), BG_SOFT, BORDER)
txt(s, Inches(1.4), Inches(2.2), Inches(4.7), Inches(0.4), "What is SQL Injection?", 16, RED, True)
txt(s, Inches(1.4), Inches(2.7), Inches(4.7), Inches(1.0),
    "When you type your username into a login form,\n"
    "the website asks its database: \"Find this user.\"\n\n"
    "But if the attacker types a command like ' OR 1=1 --\n"
    "the database gets tricked into revealing ALL users.", 13, DARK, False)

# 4 detection methods
methods = [
    ("Error-Based", "We inject bad SQL and check\nif the database shows errors\nlike 'syntax error'", RED),
    ("Time-Based Blind", "We tell the database to\nsleep for 6 seconds. If the\npage takes 6s → it's vulnerable", PURPLE),
    ("Boolean Blind", "We ask TRUE vs FALSE\nquestions. If page content\nchanges → database listens", BLUE),
    ("Union-Based", "We append extra queries\nto merge our data with\nthe original results", ORANGE),
]
for i, (title, desc, color) in enumerate(methods):
    left = Inches(7) if i < 2 else Inches(1)
    top_offset = Inches(2.0) if i < 2 else Inches(4.4)
    top = top_offset + Inches((i % 2) * 2.3)
    if i >= 2:
        left = Inches(1) + Inches((i-2) * 6)
        top = Inches(4.4)
    
for i, (title, desc, color) in enumerate(methods):
    col = i % 2; row = i // 2
    left = Inches(1) + Inches(col * 6) if row == 1 else Inches(7) + Inches(col * 0) if col == 0 else Inches(10)
    # Simpler: just lay them out in a 2x2 grid on right + bottom
    
# Let me simplify this layout
# Delete previous method cards attempt and redo as simple 2x2
# Actually let me just do 4 cards in a row at the bottom
for i, (title, desc, color) in enumerate(methods):
    left = Inches(1) + Inches(i * 3.1)
    box(s, left, Inches(4.4), Inches(2.8), Inches(2.3), WHITE, BORDER)
    bar(s, left, Inches(4.4), Inches(2.8), Pt(4), color)
    txt(s, left+Inches(0.2), Inches(4.65), Inches(2.4), Inches(0.35), title, 14, color, True, PP_ALIGN.CENTER)
    txt(s, left+Inches(0.2), Inches(5.1), Inches(2.4), Inches(1.2), desc, 11, MEDIUM, False, PP_ALIGN.CENTER)


# ═══════════════════════════════════════════
#   SLIDE 7 — SMART TESTING LOGIC
# ═══════════════════════════════════════════
s = prs.slides.add_slide(prs.slide_layouts[6]); bg(s)
bar(s, Inches(0), Inches(0), prs.slide_width, Inches(0.06), PURPLE)
txt(s, Inches(1), Inches(0.5), Inches(5), Inches(0.4), "WHAT MAKES US DIFFERENT", 13, PURPLE, True)
txt(s, Inches(1), Inches(1.0), Inches(10), Inches(0.6), "We Test Every Input — One at a Time", 36, DARK, True)
txt(s, Inches(1), Inches(1.8), Inches(10), Inches(0.5),
    "Basic scanners only test the first input field and skip the rest.\n"
    "VulnScan Pro isolates each parameter to pinpoint the exact vulnerable field.", 15, MEDIUM, False)

# Visual form iterations
form_box = box(s, Inches(1), Inches(2.8), Inches(11.3), Inches(4.0), BG_SOFT, BORDER)
txt(s, Inches(1.4), Inches(2.95), Inches(4), Inches(0.4), "Login Form Example", 14, PURPLE, True)

iters = [
    ("Test 1:", "username", "ATTACK PAYLOAD", "password", "safe value", "remember", "safe value"),
    ("Test 2:", "username", "safe value", "password", "ATTACK PAYLOAD", "remember", "safe value"),
    ("Test 3:", "username", "safe value", "password", "safe value", "remember", "ATTACK PAYLOAD"),
]
for i, (label, n1, v1, n2, v2, n3, v3) in enumerate(iters):
    top = Inches(3.5) + Inches(i * 1.0)
    color = [RED, ORANGE, PURPLE][i]
    
    box(s, Inches(1.4), top, Inches(10.5), Inches(0.8), WHITE, BORDER)
    bar(s, Inches(1.4), top, Pt(5), Inches(0.8), color)
    txt(s, Inches(1.7), top+Inches(0.15), Inches(1.2), Inches(0.5), label, 13, color, True)
    
    fields = [(n1, v1), (n2, v2), (n3, v3)]
    for j, (name, val) in enumerate(fields):
        fl = Inches(3.0) + Inches(j * 3.2)
        is_attack = "ATTACK" in val
        txt(s, fl, top+Inches(0.05), Inches(1.2), Inches(0.3), name+":", 10, LIGHT, True)
        vc = RED if is_attack else GREEN
        txt(s, fl, top+Inches(0.35), Inches(2.8), Inches(0.35), val, 12, vc, is_attack)

txt(s, Inches(1.4), Inches(6.5), Inches(10.5), Inches(0.3),
    "→  Result: We know EXACTLY which field is broken, not just \"the form has a problem\"", 13, DARK, True, PP_ALIGN.CENTER)


# ═══════════════════════════════════════════
#   SLIDE 8 — DNS IN SIMPLE TERMS
# ═══════════════════════════════════════════
s = prs.slides.add_slide(prs.slide_layouts[6]); bg(s)
bar(s, Inches(0), Inches(0), prs.slide_width, Inches(0.06), GREEN)
txt(s, Inches(1), Inches(0.5), Inches(5), Inches(0.4), "KEY FEATURE", 13, GREEN, True)
txt(s, Inches(1), Inches(1.0), Inches(10), Inches(0.6), "DNS Recon — Reading the Internet's Phone Book", 36, DARK, True)
txt(s, Inches(1), Inches(1.8), Inches(10), Inches(0.5),
    "DNS is like the phone book of the internet. It maps website names to server addresses.\n"
    "Our scanner reads this phone book to discover hidden infrastructure and security gaps.", 15, MEDIUM, False)

dns_features = [
    ("🌐", "Find Hidden Subdomains", "Like discovering admin.example.com\nor staging.example.com that\nnobody linked to publicly", SKY),
    ("📧", "Email Security Check", "Tests if attackers can send\nfake emails pretending to be\nyour domain (SPF/DKIM/DMARC)", RED),
    ("🔄", "Reverse IP Lookup", "Finds other websites hosted\non the same server IP to map\nshared infrastructure", PURPLE),
    ("🗂️", "Zone Transfer Test", "Checks if the entire DNS\ndatabase is accidentally\nexposed to anyone who asks", ORANGE),
]
for i, (icon, title, body, color) in enumerate(dns_features):
    left = Inches(0.8) + Inches(i * 3.2)
    card(s, left, Inches(2.8), Inches(2.9), Inches(2.0), color, icon, title, body)

# Bottom: what we query
box(s, Inches(0.8), Inches(5.3), Inches(11.7), Inches(1.4), BG_SOFT, BORDER)
txt(s, Inches(1.2), Inches(5.45), Inches(11), Inches(0.3), "Records We Analyze", 13, GREEN, True)
txt(s, Inches(1.2), Inches(5.85), Inches(11), Inches(0.6),
    "A (IP Address)  ·  AAAA (IPv6)  ·  MX (Mail Servers)  ·  NS (Name Servers)  ·  TXT (SPF/DKIM)\n"
    "CNAME (Aliases)  ·  SOA (Primary Server)  ·  CAA (Certificate Authority)  ·  SRV (Services)", 12, MEDIUM, False, PP_ALIGN.CENTER)


# ═══════════════════════════════════════════
#   SLIDE 9 — BACKTEST RESULTS
# ═══════════════════════════════════════════
s = prs.slides.add_slide(prs.slide_layouts[6]); bg(s)
bar(s, Inches(0), Inches(0), prs.slide_width, Inches(0.06), GREEN)
txt(s, Inches(1), Inches(0.5), Inches(5), Inches(0.4), "PROVEN ACCURACY", 13, GREEN, True)
txt(s, Inches(1), Inches(1.0), Inches(10), Inches(0.6), "39 Tests. 39 Passed. 0 False Positives.", 36, DARK, True)
txt(s, Inches(1), Inches(1.8), Inches(10), Inches(0.5),
    "We built a deliberately vulnerable test server and verified every scanner module catches\n"
    "real vulnerabilities while correctly ignoring safe pages (no false alarms).", 14, MEDIUM, False)

# Simple results grid
mods = [
    ("Header Scanner", "9/9", GREEN),
    ("XSS Scanner", "2/2", GREEN),
    ("SQLi Scanner", "2/2", GREEN),
    ("Crawler", "6/6", GREEN),
    ("Tech Fingerprint", "5/5", GREEN),
    ("JS Analyzer", "7/7", GREEN),
    ("Port Scanner", "1/1", GREEN),
    ("DNS Recon", "4/4", GREEN),
    ("SSL Scanner", "4/4", GREEN),
]
for i, (name, score, color) in enumerate(mods):
    col = i % 3; row = i // 3
    left = Inches(1.5) + Inches(col * 3.6)
    top = Inches(2.8) + Inches(row * 1.15)
    box(s, left, top, Inches(3.2), Inches(0.9), WHITE, BORDER)
    bar(s, left, top, Pt(5), Inches(0.9), color)
    txt(s, left+Inches(0.3), top+Inches(0.15), Inches(2.0), Inches(0.6), name, 13, DARK, True)
    txt(s, left+Inches(2.2), top+Inches(0.15), Inches(0.8), Inches(0.6), score, 18, GREEN, True, PP_ALIGN.RIGHT)

# Big score
box(s, Inches(3.5), Inches(6.0), Inches(6.3), Inches(0.9), RGBColor(0xEC, 0xFD, 0xF5), GREEN)
txt(s, Inches(3.5), Inches(6.1), Inches(6.3), Inches(0.7), "Overall Accuracy:  100%  ✓", 22, GREEN, True, PP_ALIGN.CENTER)


# ═══════════════════════════════════════════
#   SLIDE 10 — VS COMPETITORS
# ═══════════════════════════════════════════
s = prs.slides.add_slide(prs.slide_layouts[6]); bg(s)
bar(s, Inches(0), Inches(0), prs.slide_width, Inches(0.06), BLUE)
txt(s, Inches(1), Inches(0.5), Inches(5), Inches(0.4), "COMPARISON", 13, BLUE, True)
txt(s, Inches(1), Inches(1.0), Inches(10), Inches(0.6), "How We Compare to Big Players", 36, DARK, True)

# Simple comparison
comp = [
    ("Feature",           "VulnScan Pro", "OWASP ZAP", "Nessus",  "Burp Suite"),
    ("One-Click Scan",    "✅",            "❌",         "✅",      "❌"),
    ("Blind SQLi",        "✅",            "✅",         "✅",      "✅"),
    ("DNS + Subdomains",  "✅",            "❌",         "✅",      "❌"),
    ("JS Secret Finder",  "✅",            "❌",         "❌",      "✅"),
    ("SSL Audit",         "✅",            "❌",         "✅",      "❌"),
    ("Free to Use",       "✅",            "✅",         "❌",      "❌"),
    ("Modern Web UI",     "✅",            "❌",         "✅",      "✅"),
    ("No Java Needed",    "✅",            "❌",         "❌",      "❌"),
]

for i, row in enumerate(comp):
    top = Inches(2.0) + Inches(i * 0.52)
    if i == 0:
        box(s, Inches(1), top, Inches(11.3), Inches(0.48), BLUE)
        col_c = WHITE
    else:
        bg_c = BG_SOFT if i % 2 == 0 else WHITE
        box(s, Inches(1), top, Inches(11.3), Inches(0.48), bg_c, BORDER)
        col_c = None
    
    widths = [3.2, 2.0, 1.8, 1.5, 1.8]
    left = Inches(1.3)
    for j, (val, w) in enumerate(zip(row, widths)):
        if col_c:
            c = col_c
        elif val == "✅":
            c = GREEN
        elif val == "❌":
            c = RED
        else:
            c = DARK
        b = (i == 0) or (j == 0)
        al = PP_ALIGN.LEFT if j == 0 else PP_ALIGN.CENTER
        txt(s, left, top+Inches(0.08), Inches(w), Inches(0.35), val, 12, c, b, al)
        left += Inches(w + 0.15)


# ═══════════════════════════════════════════
#   SLIDE 11 — FUTURE SCOPE
# ═══════════════════════════════════════════
s = prs.slides.add_slide(prs.slide_layouts[6]); bg(s)
bar(s, Inches(0), Inches(0), prs.slide_width, Inches(0.06), PURPLE)
txt(s, Inches(1), Inches(0.5), Inches(5), Inches(0.4), "FUTURE SCOPE", 13, PURPLE, True)
txt(s, Inches(1), Inches(1.0), Inches(10), Inches(0.6), "What's Coming Next", 36, DARK, True)

futures = [
    ("🔐", "Login & Scan", "Scan pages behind\nlogin walls automatically", BLUE),
    ("🌐", "JS App Support", "Use a headless browser to\nscan React/Angular apps", SKY),
    ("🛡️", "WAF Bypass", "User-Agent rotation and\npayload encoding to evade\nfirewalls", RED),
    ("💻", "More Attacks", "Command injection, path\ntraversal, SSRF, and\nIDOR testing", ORANGE),
    ("🔄", "CI/CD Pipeline", "Auto-scan on every\nGitHub push or\ndeployment", GREEN),
    ("📊", "Trends Over Time", "Track your security\nscore improvements\nacross releases", PURPLE),
]
for i, (icon, title, body, color) in enumerate(futures):
    col = i % 3; row = i // 3
    left = Inches(0.8) + Inches(col * 4.1)
    top = Inches(2.0) + Inches(row * 2.5)
    card(s, left, top, Inches(3.7), Inches(2.1), color, icon, title, body)


# ═══════════════════════════════════════════
#   SLIDE 12 — THANK YOU
# ═══════════════════════════════════════════
s = prs.slides.add_slide(prs.slide_layouts[6]); bg(s)
bar(s, Inches(0), Inches(0), prs.slide_width, Inches(0.06), BLUE)

txt(s, Inches(1), Inches(2.2), Inches(11), Inches(0.5), "VULNSCAN PRO", 18, BLUE, True, PP_ALIGN.CENTER)
txt(s, Inches(1), Inches(2.9), Inches(11), Inches(1.0), "Thank You!", 52, DARK, True, PP_ALIGN.CENTER)
txt(s, Inches(2), Inches(4.2), Inches(9), Inches(0.5), "Questions & Discussion", 20, MEDIUM, False, PP_ALIGN.CENTER)

for i, (v, l) in enumerate([("9 Modules", "Full-stack scanning"), ("100% Accuracy", "Zero false positives"), ("6 SQLi Methods", "Including blind detection")]):
    left = Inches(1.8) + Inches(i * 3.5)
    box(s, left, Inches(5.2), Inches(3), Inches(1.2), BG_SOFT, BORDER)
    txt(s, left, Inches(5.35), Inches(3), Inches(0.45), v, 20, BLUE, True, PP_ALIGN.CENTER)
    txt(s, left, Inches(5.8), Inches(3), Inches(0.4), l, 12, MEDIUM, False, PP_ALIGN.CENTER)


# ═══════════════════════════════════════════
#   SAVE
# ═══════════════════════════════════════════
output_path = os.path.join(os.path.dirname(__file__), "VulnScan_Pro_Simple.pptx")
prs.save(output_path)
print(f"Presentation saved to: {output_path}")
print(f"Total slides: {len(prs.slides)}")
