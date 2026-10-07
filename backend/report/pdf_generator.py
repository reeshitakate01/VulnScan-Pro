import os
from datetime import datetime
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
from reportlab.lib.units import inch

# Color mapping for severities
SEVERITY_COLORS = {
    "CRITICAL": colors.red,
    "HIGH": colors.orange,
    "MEDIUM": colors.gold,
    "LOW": colors.skyblue,
    "INFO": colors.lightgrey
}

class NumberedCanvas(SimpleDocTemplate):
    """ Canvas class for adding a footer to each page. """
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        
    def build(self, flowables):
        super().build(flowables, onFirstPage=self._header_footer, onLaterPages=self._header_footer)
        
    def _header_footer(self, canvas, doc):
        canvas.saveState()
        canvas.setFont('Helvetica', 9)
        canvas.setFillColor(colors.grey)
        
        # Footer
        footer_text = f"CONFIDENTIAL - Page {doc.page}"
        canvas.drawCentredString(letter[0]/2.0, 0.5 * inch, footer_text)
        
        canvas.restoreState()

def create_table_for_findings(findings, col_widths):
    # Header
    data = [["Finding", "Severity", "Description", "Recommendation"]]
    styles = [
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#2c3e50')),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
        ('GRID', (0, 0), (-1, -1), 1, colors.black),
        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ('WORDWRAP', (0, 0), (-1, -1), True)
    ]
    
    for row_idx, finding in enumerate(findings, start=1):
        severity = finding.get("Severity", "INFO")
        bg_color = SEVERITY_COLORS.get(severity, colors.lightgrey)
        
        data.append([
            finding.get("Finding", ""),
            severity,
            finding.get("Description", ""),
            finding.get("Recommendation", "")
        ])
        
        # Style the severity column
        styles.append(('BACKGROUND', (1, row_idx), (1, row_idx), bg_color))
        styles.append(('TEXTCOLOR', (1, row_idx), (1, row_idx), colors.black if severity in ['MEDIUM', 'INFO'] else colors.whitesmoke))
        
    table = Table(data, colWidths=col_widths, repeatRows=1)
    table.setStyle(TableStyle(styles))
    return table

def generate_pdf(scan_id, scan_data):
    """
    scan_data should be a dict containing:
    {
        "url": "http://example.com",
        "date": "2026-02-23 10:00:00",
        "score": 85,
        "grade": "B",
        "summary": "...",
        "modules": {
            "port_scan": [...findings...],
            "headers": [...findings...]
        }
    }
    """
    filepath = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..', 'reports', f"{scan_id}.pdf"))
    doc = NumberedCanvas(filepath, pagesize=letter)
    
    styles = getSampleStyleSheet()
    title_style = styles['Title']
    heading1_style = styles['Heading1']
    heading2_style = styles['Heading2']
    normal_style = styles['Normal']
    
    custom_normal = ParagraphStyle(
        'CustomNormal',
        parent=styles['Normal'],
        spaceAfter=12
    )
    
    story = []
    
    # --- Cover Page ---
    story.append(Spacer(1, 2*inch))
    story.append(Paragraph("<b>VulnScan Pro</b>", ParagraphStyle(
        'CoverTitle', parent=title_style, fontSize=36, textColor=colors.HexColor('#2c3e50')
    )))
    story.append(Spacer(1, 0.5*inch))
    story.append(Paragraph("Security Assessment Report", ParagraphStyle(
        'CoverSubTitle', parent=title_style, fontSize=24, textColor=colors.grey
    )))
    story.append(Spacer(1, 1*inch))
    
    story.append(Paragraph(f"<b>Target URL:</b> {scan_data.get('url', 'Unknown')}", custom_normal))
    story.append(Paragraph(f"<b>Scan Date:</b> {scan_data.get('date', datetime.now().strftime('%Y-%m-%d %H:%M:%S'))}", custom_normal))
    story.append(Paragraph(f"<b>Overall Score:</b> {scan_data.get('score', 0)}/100 (Grade: {scan_data.get('grade', 'F')})", custom_normal))
    
    story.append(PageBreak())
    
    # --- Executive Summary ---
    story.append(Paragraph("Executive Summary", heading1_style))
    story.append(Paragraph(scan_data.get("summary", "No summary provided."), custom_normal))
    story.append(Spacer(1, 0.2*inch))
    
    # Chart or simple stats could go here
    story.append(PageBreak())
    
    # --- OWASP Mapping ---
    owasp_summary = scan_data.get("owasp_summary", {})
    if owasp_summary:
        story.append(Paragraph("OWASP Mapping", heading1_style))
        story.append(Spacer(1, 0.1*inch))
        
        owasp_data = [["OWASP Category", "CWE", "CVSS", "Finding", "Severity"]]
        owasp_styles = [
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#2c3e50')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('GRID', (0, 0), (-1, -1), 1, colors.black),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('WORDWRAP', (0, 0), (-1, -1), True)
        ]
        
        row_idx = 1
        for cat_id, cat_info in owasp_summary.items():
            if cat_info.get("count", 0) > 0:
                owasp_data.append([f"{cat_id} - {cat_info['name']}", "", "", "", ""])
                owasp_styles.append(('SPAN', (0, row_idx), (-1, row_idx)))
                owasp_styles.append(('BACKGROUND', (0, row_idx), (-1, row_idx), colors.HexColor('#bdc3c7')))
                owasp_styles.append(('TEXTCOLOR', (0, row_idx), (-1, row_idx), colors.black))
                owasp_styles.append(('FONTNAME', (0, row_idx), (-1, row_idx), 'Helvetica-Bold'))
                row_idx += 1
                
                cat_findings = sorted(cat_info.get("findings", []), key=lambda x: x.get("cvss_score", 0), reverse=True)
                for f in cat_findings:
                    sev = f.get("Severity", "INFO")
                    bg_color = SEVERITY_COLORS.get(sev, colors.lightgrey)
                    text_color = colors.black if sev in ['MEDIUM', 'INFO', 'LOW'] else colors.whitesmoke
                    
                    owasp_data.append([
                        "",
                        f.get("cwe", "N/A"),
                        str(f.get("cvss_score", "N/A")),
                        f.get("Finding", "Unknown"),
                        sev
                    ])
                    owasp_styles.append(('BACKGROUND', (4, row_idx), (4, row_idx), bg_color))
                    owasp_styles.append(('TEXTCOLOR', (4, row_idx), (4, row_idx), text_color))
                    row_idx += 1
                    
        if row_idx > 1:
            owasp_col_widths = [1.8*inch, 0.7*inch, 0.6*inch, 2.5*inch, 0.9*inch]
            owasp_table = Table(owasp_data, colWidths=owasp_col_widths, repeatRows=1)
            owasp_table.setStyle(TableStyle(owasp_styles))
            story.append(owasp_table)
            story.append(PageBreak())

    # --- Detailed Findings by Module ---
    col_widths = [1.5*inch, 0.8*inch, 2.5*inch, 1.7*inch] # Total ~6.5 usable inches
    
    modules = scan_data.get("modules", {})
    if not modules:
        story.append(Paragraph("No module data available.", normal_style))
    
    for mod_name, findings in modules.items():
        if not findings:
            continue
            
        story.append(Paragraph(mod_name.replace('_', ' ').title(), heading1_style))
        story.append(Spacer(1, 0.1*inch))
        
        table = create_table_for_findings(findings, col_widths)
        story.append(table)
        story.append(Spacer(1, 0.3*inch))
        
    story.append(PageBreak())
        
    # --- Remediation Checklist ---
    story.append(Paragraph("Remediation Checklist", heading1_style))
    story.append(Paragraph("Follow these recommendations to improve your security posture:", custom_normal))
    
    # Simple list of all critical/high recommendations
    checklist = []
    for mod_name, findings in modules.items():
        for f in findings:
            if f.get("Severity") in ["CRITICAL", "HIGH"]:
                rec = f.get("Recommendation", "")
                if rec and rec not in checklist:
                    checklist.append(rec)
                    
    for i, item in enumerate(checklist, 1):
        story.append(Paragraph(f"• {item}", custom_normal))
        
    doc.build(story)
    return filepath
