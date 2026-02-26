"""
Report endpoint — adds /report to the Gate proxy.

Generates compliance reports as JSON, Markdown, or HTML.
PDF generation uses markdown-to-HTML conversion with print-ready CSS.
"""

from fastapi import APIRouter, Query
from fastapi.responses import HTMLResponse, JSONResponse
from typing import Optional

from .events import EventStore
from .report import generate_report_data, render_report_markdown

router = APIRouter()


def get_report_html(markdown_content: str, title: str) -> str:
    """Convert markdown report to print-ready HTML with professional styling."""
    # Convert basic markdown to HTML inline (no external deps needed)
    html_body = markdown_content

    # Headers
    import re
    html_body = re.sub(r'^### (.+)$', r'<h3>\1</h3>', html_body, flags=re.MULTILINE)
    html_body = re.sub(r'^## (.+)$', r'<h2>\1</h2>', html_body, flags=re.MULTILINE)
    html_body = re.sub(r'^# (.+)$', r'<h1>\1</h1>', html_body, flags=re.MULTILINE)

    # Bold
    html_body = re.sub(r'\*\*(.+?)\*\*', r'<strong>\1</strong>', html_body)

    # Lists
    html_body = re.sub(r'^- (.+)$', r'<li>\1</li>', html_body, flags=re.MULTILINE)
    html_body = re.sub(r'(<li>.*</li>\n)+', lambda m: f'<ul>{m.group(0)}</ul>', html_body)

    # Blockquotes
    html_body = re.sub(r'^> (.+)$', r'<blockquote>\1</blockquote>', html_body, flags=re.MULTILINE)

    # Horizontal rules
    html_body = html_body.replace('---', '<hr>')

    # Links
    html_body = re.sub(r'\[(.+?)\]\((.+?)\)', r'<a href="\2">\1</a>', html_body)

    # Italics
    html_body = re.sub(r'\*(.+?)\*', r'<em>\1</em>', html_body)

    # Paragraphs (blank lines)
    html_body = re.sub(r'\n\n', '</p><p>', html_body)

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>{title}</title>
<style>
  @page {{ margin: 1in; }}
  body {{
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
    max-width: 800px;
    margin: 0 auto;
    padding: 40px;
    color: #1a1a1a;
    line-height: 1.6;
  }}
  h1 {{
    color: #0f172a;
    border-bottom: 3px solid #3b82f6;
    padding-bottom: 12px;
    font-size: 28px;
  }}
  h2 {{
    color: #1e40af;
    margin-top: 32px;
    font-size: 20px;
    border-bottom: 1px solid #e2e8f0;
    padding-bottom: 8px;
  }}
  h3 {{
    color: #334155;
    font-size: 16px;
  }}
  ul {{
    padding-left: 24px;
  }}
  li {{
    margin-bottom: 6px;
  }}
  blockquote {{
    background: #f0fdf4;
    border-left: 4px solid #22c55e;
    padding: 12px 16px;
    margin: 16px 0;
    border-radius: 0 8px 8px 0;
  }}
  blockquote.warning {{
    background: #fef2f2;
    border-left-color: #ef4444;
  }}
  hr {{
    border: none;
    border-top: 1px solid #e2e8f0;
    margin: 32px 0;
  }}
  strong {{
    color: #0f172a;
  }}
  .footer {{
    text-align: center;
    color: #94a3b8;
    font-size: 12px;
    margin-top: 48px;
  }}
  @media print {{
    body {{ padding: 0; }}
    h2 {{ page-break-before: auto; }}
  }}
</style>
</head>
<body>
{html_body}
</body>
</html>"""


def create_report_router(event_store: EventStore) -> APIRouter:
    """Create the report router with access to the event store."""

    @router.get("/report")
    async def generate_report(
        start: Optional[str] = Query(None, description="Start date (ISO 8601)"),
        end: Optional[str] = Query(None, description="End date (ISO 8601)"),
        format: str = Query("html", description="Output format: json, markdown, html"),
        title: str = Query("AI Activity Compliance Report", description="Report title"),
    ):
        """Generate a compliance report for the given period."""
        report_data = generate_report_data(
            event_store=event_store,
            start_date=start,
            end_date=end,
            title=title,
        )

        if format == "json":
            return JSONResponse(content=report_data)

        markdown = render_report_markdown(report_data)

        if format == "markdown":
            return JSONResponse(content={"markdown": markdown})

        # Default: HTML (print to PDF from browser)
        html = get_report_html(markdown, title)
        return HTMLResponse(content=html)

    return router
