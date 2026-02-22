# PDF Report Export Feature

## Overview

The **PDF Report Export** feature allows users to generate professional vulnerability scan reports in PDF format. Each report is generated per scan/target and includes comprehensive vulnerability details, severity breakdown, and AI analysis.

## Features

### ✅ What's Included

1. **Executive Summary** - Quick overview of scan results
2. **Severity Breakdown** - Vulnerabilities categorized by severity (Critical, High, Medium, Low, Info)
3. **Detailed Findings** - For each vulnerability:
   - Name and severity level
   - Host and URL information
   - CVE ID and CVSS Score
   - Vulnerability type and template ID
   - Description and tags
   - AI analysis (business impact, remediation)
   - References and evidence

4. **Professional Formatting** - Styled tables, proper pagination, and clear sections

## API Endpoints

### 1. Download PDF Report for a Specific Scan

**Endpoint:**
```bash
GET /api/scans/{scan_id}/report/pdf
```

**Description:** Generate and download a PDF report for a completed scan

**Parameters:**
- `scan_id` (path) - The scan ID to generate report for

**Response:** PDF file (application/pdf)

**Example:**
```bash
curl -O http://localhost:8000/api/scans/abc123/report/pdf \
  -H "Accept: application/pdf"
```

**Frontend Usage:**
The frontend includes a **"↓ PDF"** button next to each completed scan that automatically triggers the download.

### 2. Bulk PDF Export (Optional)

**Endpoint:**
```bash
GET /api/scans/report/bulk-pdf
```

**Description:** Generate a PDF report for all scans (currently generates report for the first target)

**Response:** PDF file (application/pdf)

## Frontend Integration

### PDF Download Button

- **Location:** Next to each scan in the "Scans Management" view
- **Visibility:** Only appears for completed scans
- **Style:** Green button with "↓ PDF" label
- **Action:** Clicking downloads the PDF report automatically

### UI Code
```jsx
{sc.status === "completed" && (
  <button
    onClick={e => {
      e.stopPropagation();
      const link = document.createElement("a");
      link.href = `/api/scans/${sc.scan_id}/report/pdf`;
      link.download = `report_${sc.scan_id}.pdf`;
      document.body.appendChild(link);
      link.click();
      document.body.removeChild(link);
    }}
    title="Download PDF Report"
    style={{ padding: "4px 8px", borderRadius: 4, border: "1px solid #22c55e", background: "#10b98115", color: "#10b981", fontSize: 11, cursor: "pointer", fontWeight: 600 }}>
    ↓ PDF
  </button>
)}
```

## Dependencies

- **reportlab** (v4.0.9) - PDF generation library

## File Structure

### Backend
```
backend/
├── modules/
│   ├── pdf_report.py          # PDF report generator
│   └── ...
├── main.py                    # API endpoints for PDF export
├── requirements.txt           # Updated with reportlab
└── ...
```

### Frontend
```
frontend/
├── Dashboard.jsx              # PDF download button added to Scans view
└── ...
```

## Usage Example

### 1. Run a Scan
```bash
curl -X POST http://localhost:8000/api/scans \
  -H "Content-Type: application/json" \
  -d '{
    "target": "https://example.com",
    "scan_type": "full",
    "scanner_engine": "nuclei"
  }'
```

### 2. Wait for Scan to Complete
Monitor via the Dashboard or use `/api/scans` endpoint

### 3. Download PDF Report
**Option A: Using Frontend UI**
- Go to Scans view
- Find your completed scan
- Click the green "↓ PDF" button

**Option B: Using API**
```bash
curl -O http://localhost:8000/api/scans/{scan_id}/report/pdf
```

## Report Customization

To customize report appearance, edit `backend/modules/pdf_report.py`:

- **Colors**: Modify `severity_colors` dictionary
- **Fonts**: Change font names in ParagraphStyle definitions
- **Layout**: Adjust spacing and table structure in `_build_*` methods
- **Content**: Add/remove sections in `generate_report()` method

## Error Handling

If PDF generation fails:
- **404 Not Found**: Scan doesn't exist or has no findings
- **500 Internal Error**: PDF generation error (check logs)

View logs:
```bash
sudo docker logs vulnerability-scanner-backend --tail=100
```

## Performance

- **Small Scans** (<100 findings): ~500ms
- **Medium Scans** (100-500 findings): ~1-2s
- **Large Scans** (500+ findings): ~2-5s

PDFs are generated on-demand (not cached).

## Future Enhancements

Potential improvements:
1. Batch PDF generation for multiple scans
2. Custom report templates
3. Email delivery of reports
4. Historical trend charts in PDFs
5. Compliance frameworks (OWASP, PCI-DSS)
6. CSV/Excel export options
7. Report scheduling and automation

## Support

For issues or feature requests:
1. Check application logs: `sudo docker logs vulnerability-scanner-backend`
2. Verify reportlab is installed: `pip show reportlab`
3. Test endpoint directly: `curl http://localhost:8000/api/health`
