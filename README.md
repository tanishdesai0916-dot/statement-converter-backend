# StatementIQ — Python Backend

## Quick Start

```bash
cd backend

# 1. Create a virtual environment
python -m venv venv
venv\Scripts\activate        # Windows
# source venv/bin/activate   # macOS / Linux

# 2. Install dependencies
pip install -r requirements.txt

# 3. Start the server
uvicorn main:app --reload --host 0.0.0.0 --port 8000
```

The API will be available at **http://localhost:8000**

Health check: http://localhost:8000/health

## OCR (Kotak Credit Card only)

Install these native tools:
- **Ghostscript 10.x**: https://www.ghostscript.com/releases/gsdnld.html
- **Tesseract 5.x**: https://github.com/UB-Mannheim/tesseract/wiki

Update the paths in `main.py` if they differ from the defaults:
```python
TESSERACT_EXE = r"C:\Program Files\Tesseract-OCR\tesseract.exe"
GS_EXE        = r"C:\Program Files\gs\gs10.06.0\bin\gswin64c.exe"
```

## API

### POST /convert

Multipart form fields:
| Field      | Type   | Description                              |
|------------|--------|------------------------------------------|
| `file`     | file   | PDF statement                            |
| `mode`     | string | `"pms"` or `"kotak"`                     |
| `sub_mode` | string | `"bank"` or `"cc"` (for kotak mode only) |
| `password` | string | PDF password (optional, CC only)         |

Response:
```json
{
  "ok": true,
  "report": { "pdfName": "...", "rowsExtracted": 142, "status": "MATCH", ... },
  "files": { "xlsx": "<base64>", "xml": "<base64>" }
}
```

### GET /health

Returns OCR availability and tool paths.
