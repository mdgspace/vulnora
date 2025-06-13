from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors
import os
from datetime import datetime

class DomainService:

    supported_attacks = {
        "xss": "Cross-Site Scripting",
        "sql_injection": "SQL Injection",
        # Add more attack types here
    }

    # Store scan results temporarily (in production, use database)
    scan_results_cache = {}

    @staticmethod
    def scan_domain(domain, attacks):
        results = {}

        for attack in attacks:
            if attack == "xss":
                results['xss'] = DomainService.check_xss(domain)
            elif attack == "sql_injection":
                results['sql_injection'] = DomainService.check_sql_injection(domain)
            # Add more attack types here
            else:
                results[attack] = "Unknown attack type"

        scan_data = {
            "domain": domain,
            "results": results,
            "timestamp": datetime.now().isoformat()
        }
        
        # Cache the results for PDF generation
        DomainService.scan_results_cache[domain] = scan_data
        
        return scan_data

    # Define methods for checking vulnerabilities over here
    @staticmethod
    def check_xss(domain):
        # Mock logic for XSS vulnerability
        return "No XSS vulnerability found"

    @staticmethod
    def check_sql_injection(domain):
        # Mock logic for SQLi vulnerability
        return "Potential SQL injection found"
    
    @classmethod
    def get_supported_attacks(cls):
        return cls.supported_attacks

    @staticmethod
    def generate_pdf_report(domain):
        # Get cached scan results
        scan_data = DomainService.scan_results_cache.get(domain)
        if not scan_data:
            raise Exception("No scan data found for this domain")

        # Create PDF directory if it doesn't exist
        pdf_dir = "static/reports"
        os.makedirs(pdf_dir, exist_ok=True)
        
        # Generate PDF filename
        safe_domain = domain.replace('/', '_').replace(':', '_')
        pdf_filename = f"{safe_domain}_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
        pdf_path = os.path.join(pdf_dir, pdf_filename)
        
        # Create PDF
        doc = SimpleDocTemplate(pdf_path, pagesize=letter)
        styles = getSampleStyleSheet()
        story = []
        
        # Title
        title_style = ParagraphStyle(
            'CustomTitle',
            parent=styles['Heading1'],
            fontSize=24,
            spaceAfter=30,
            textColor=colors.darkblue
        )
        story.append(Paragraph("Vulnora Security Report", title_style))
        story.append(Spacer(1, 20))
        
        # Domain info
        story.append(Paragraph(f"<b>Domain:</b> {scan_data['domain']}", styles['Normal']))
        story.append(Paragraph(f"<b>Scan Date:</b> {scan_data['timestamp']}", styles['Normal']))
        story.append(Spacer(1, 20))
        
        # Results section
        story.append(Paragraph("Vulnerability Scan Results", styles['Heading2']))
        story.append(Spacer(1, 12))
        
        for attack_type, result in scan_data['results'].items():
            attack_name = DomainService.supported_attacks.get(attack_type, attack_type.replace('_', ' ').title())
            story.append(Paragraph(f"<b>{attack_name}:</b>", styles['Heading3']))
            story.append(Paragraph(result, styles['Normal']))
            story.append(Spacer(1, 12))
        
        doc.build(story)
        
        # Return the API download URL
        return f"http://localhost:5001/api/download/{pdf_filename}"