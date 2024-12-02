"""
HTML report generator for Movery
"""
import os
from typing import List, Dict, Any
import json
import datetime
from jinja2 import Environment, FileSystemLoader
import logging
import base64
import plotly.graph_objects as go
import plotly.express as px
import pandas as pd

from movery.config.config import config
from movery.utils.logging import get_logger
from movery.detectors.vulnerability import VulnerabilityMatch

logger = get_logger(__name__)

class HTMLReporter:
    """Generate HTML vulnerability reports"""
    
    def __init__(self, template_dir: str = "templates"):
        self.template_dir = template_dir
        self.env = Environment(loader=FileSystemLoader(template_dir))
        
    def generate_report(self, matches: List[VulnerabilityMatch],
                       output_file: str):
        """Generate HTML report from vulnerability matches"""
        template = self.env.get_template("report.html")
        
        # Prepare report data
        report_data = self._prepare_report_data(matches)
        
        # Generate charts
        charts = self._generate_charts(matches)
        
        # Render template
        html = template.render(
            report=report_data,
            charts=charts,
            generated_at=datetime.datetime.now().isoformat()
        )
        
        # Write report
        os.makedirs(os.path.dirname(output_file), exist_ok=True)
        with open(output_file, "w", encoding="utf-8") as f:
            f.write(html)
            
        logger.info(f"Generated HTML report: {output_file}")
        
    def _prepare_report_data(self, matches: List[VulnerabilityMatch]) -> Dict:
        """Prepare report data from matches"""
        vulnerabilities = []
        files = set()
        severities = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        
        for match in matches:
            vulnerabilities.append({
                "id": match.signature.id,
                "name": match.signature.name,
                "description": match.signature.description,
                "severity": match.signature.severity,
                "cwe_id": match.signature.cwe_id,
                "cve_id": match.signature.cve_id,
                "file": match.file,
                "line_start": match.line_start,
                "line_end": match.line_end,
                "matched_code": match.matched_code,
                "confidence": match.confidence,
                "context": match.context
            })
            
            files.add(match.file)
            severities[match.signature.severity] = \
                severities.get(match.signature.severity, 0) + 1
                
        return {
            "summary": {
                "total_vulnerabilities": len(vulnerabilities),
                "total_files": len(files),
                "severities": severities
            },
            "vulnerabilities": vulnerabilities,
            "files": sorted(list(files))
        }
        
    def _generate_charts(self, matches: List[VulnerabilityMatch]) -> Dict[str, str]:
        """Generate charts for report"""
        charts = {}
        
        # Severity distribution pie chart
        severity_counts = pd.DataFrame([
            {"severity": m.signature.severity, "count": 1}
            for m in matches
        ]).groupby("severity").sum().reset_index()
        
        fig = px.pie(severity_counts, values="count", names="severity",
                    title="Vulnerability Severity Distribution")
        charts["severity_distribution"] = self._fig_to_base64(fig)
        
        # Vulnerability types bar chart
        vuln_types = pd.DataFrame([
            {"type": m.signature.name, "count": 1}
            for m in matches
        ]).groupby("type").sum().reset_index()
        
        fig = px.bar(vuln_types, x="type", y="count",
                    title="Vulnerability Types")
        fig.update_layout(xaxis_tickangle=-45)
        charts["vulnerability_types"] = self._fig_to_base64(fig)
        
        # Files with most vulnerabilities
        file_counts = pd.DataFrame([
            {"file": m.file, "count": 1}
            for m in matches
        ]).groupby("file").sum().reset_index()
        
        file_counts = file_counts.sort_values("count", ascending=False).head(10)
        
        fig = px.bar(file_counts, x="file", y="count",
                    title="Files with Most Vulnerabilities")
        fig.update_layout(xaxis_tickangle=-45)
        charts["file_distribution"] = self._fig_to_base64(fig)
        
        # Confidence distribution histogram
        confidence_data = pd.DataFrame([
            {"confidence": m.confidence}
            for m in matches
        ])
        
        fig = px.histogram(confidence_data, x="confidence",
                          title="Detection Confidence Distribution")
        charts["confidence_distribution"] = self._fig_to_base64(fig)
        
        return charts
        
    def _fig_to_base64(self, fig: go.Figure) -> str:
        """Convert plotly figure to base64 string"""
        img_bytes = fig.to_image(format="png")
        return base64.b64encode(img_bytes).decode()

# HTML report template
REPORT_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>Movery Vulnerability Report</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            line-height: 1.6;
            margin: 0;
            padding: 20px;
        }
        
        .container {
            max-width: 1200px;
            margin: 0 auto;
        }
        
        h1, h2, h3 {
            color: #333;
        }
        
        .summary {
            background: #f5f5f5;
            padding: 20px;
            border-radius: 5px;
            margin-bottom: 30px;
        }
        
        .charts {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(500px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        
        .chart {
            background: white;
            padding: 20px;
            border-radius: 5px;
            box-shadow: 0 2px 5px rgba(0,0,0,0.1);
        }
        
        .vulnerability {
            background: white;
            padding: 20px;
            border-radius: 5px;
            box-shadow: 0 2px 5px rgba(0,0,0,0.1);
            margin-bottom: 20px;
        }
        
        .vulnerability-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 10px;
        }
        
        .severity {
            padding: 5px 10px;
            border-radius: 3px;
            color: white;
            font-weight: bold;
        }
        
        .severity.CRITICAL { background: #dc3545; }
        .severity.HIGH { background: #fd7e14; }
        .severity.MEDIUM { background: #ffc107; }
        .severity.LOW { background: #28a745; }
        
        .code {
            background: #f8f9fa;
            padding: 15px;
            border-radius: 5px;
            font-family: monospace;
            white-space: pre-wrap;
            margin: 10px 0;
        }
        
        .context {
            margin-top: 10px;
            font-size: 0.9em;
            color: #666;
        }
        
        .footer {
            margin-top: 50px;
            text-align: center;
            color: #666;
            font-size: 0.8em;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>Movery Vulnerability Report</h1>
        
        <div class="summary">
            <h2>Summary</h2>
            <p>Total Vulnerabilities: {{ report.summary.total_vulnerabilities }}</p>
            <p>Total Files: {{ report.summary.total_files }}</p>
            <p>Severity Distribution:</p>
            <ul>
            {% for severity, count in report.summary.severities.items() %}
                <li>{{ severity }}: {{ count }}</li>
            {% endfor %}
            </ul>
        </div>
        
        <div class="charts">
            <div class="chart">
                <img src="data:image/png;base64,{{ charts.severity_distribution }}"
                     alt="Severity Distribution">
            </div>
            <div class="chart">
                <img src="data:image/png;base64,{{ charts.vulnerability_types }}"
                     alt="Vulnerability Types">
            </div>
            <div class="chart">
                <img src="data:image/png;base64,{{ charts.file_distribution }}"
                     alt="File Distribution">
            </div>
            <div class="chart">
                <img src="data:image/png;base64,{{ charts.confidence_distribution }}"
                     alt="Confidence Distribution">
            </div>
        </div>
        
        <h2>Vulnerabilities</h2>
        {% for vuln in report.vulnerabilities %}
        <div class="vulnerability">
            <div class="vulnerability-header">
                <h3>{{ vuln.name }}</h3>
                <span class="severity {{ vuln.severity }}">{{ vuln.severity }}</span>
            </div>
            
            <p>{{ vuln.description }}</p>
            
            {% if vuln.cwe_id %}
            <p>CWE: {{ vuln.cwe_id }}</p>
            {% endif %}
            
            {% if vuln.cve_id %}
            <p>CVE: {{ vuln.cve_id }}</p>
            {% endif %}
            
            <p>File: {{ vuln.file }}:{{ vuln.line_start }}-{{ vuln.line_end }}</p>
            <p>Confidence: {{ "%.2f"|format(vuln.confidence) }}</p>
            
            <div class="code">{{ vuln.matched_code }}</div>
            
            <div class="context">
                <h4>Context</h4>
                <p>Imports: {{ vuln.context.imports|length }}</p>
                <p>Functions: {{ vuln.context.functions|length }}</p>
                <p>Classes: {{ vuln.context.classes|length }}</p>
                <p>Variables: {{ vuln.context.variables|length }}</p>
            </div>
        </div>
        {% endfor %}
        
        <div class="footer">
            Generated at {{ generated_at }}
        </div>
    </div>
</body>
</html>
"""

# Create templates directory and save template
os.makedirs("templates", exist_ok=True)
with open("templates/report.html", "w", encoding="utf-8") as f:
    f.write(REPORT_TEMPLATE)

# Global reporter instance
reporter = HTMLReporter() 