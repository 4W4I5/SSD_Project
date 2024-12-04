# generate_report.py
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
import os


def generate_report(scan_result):
    report_name = f"report_{scan_result.id}.pdf"
    report_path = os.path.join("static", "reports", report_name)
    # Ensure the reports directory exists
    os.makedirs(os.path.dirname(report_path), exist_ok=True)

    c = canvas.Canvas(report_path, pagesize=letter)
    textobject = c.beginText(50, 750)
    textobject.setFont("Helvetica", 12)
    textobject.textLine(f"Security Scan Report for {scan_result.filename}")
    textobject.textLine(f"Scan ID: {scan_result.id}")
    # Uncomment if you have a timestamp attribute
    # textobject.textLine(f"Timestamp: {scan_result.timestamp}")
    textobject.textLine("")
    textobject.textLine("Scan Findings:")
    textobject.textLine("")

    results = scan_result.get_results()
    y_position = 700  # Adjust starting Y position

    for result in results:
        if y_position < 100:
            c.drawText(textobject)
            c.showPage()
            textobject = c.beginText(50, 750)
            textobject.setFont("Helvetica", 12)
            y_position = 750

        textobject.textLine("----------------------------------------")
        y_position -= 15

        if result.get("filename"):
            textobject.textLine(f"File: {result.get('filename')}")
            y_position -= 15

        if result.get("function_name"):
            textobject.textLine(f"Function: {result.get('function_name')}")
            y_position -= 15

        textobject.textLine(f"Issue: {result.get('issue', 'N/A')}")
        y_position -= 15

        textobject.textLine(f"Severity: {result.get('severity', 'N/A')}")
        y_position -= 15

        if result.get("line_number") and result.get("line_number") != "N/A":
            textobject.textLine(f"Line Number: {result.get('line_number')}")
            y_position -= 15

        textobject.textLine(f"Suggestion: {result.get('suggestion', 'N/A')}")
        y_position -= 15

        textobject.textLine("")
        y_position -= 15

    c.drawText(textobject)
    c.save()
    return report_name
