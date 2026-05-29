# /sic — Security Intelligence Center

Run SIC scans, check health, manage incidents, and apply AI fixes from Claude Code.

## Usage

```
/sic                         # server health check
/sic scan web                # web vulnerability scan
/sic scan recon              # recon / OSINT scan
/sic scan network            # port + network scan
/sic scan full               # all scan types in parallel
/sic incidents               # list open incidents
/sic incident <id>           # get incident detail
/sic fix <finding-id>        # apply AI-suggested fix for a finding
/sic export <scan-id>        # export scan as JSON (add ?format=csv or ?format=pdf)
/sic bugs                    # show BUGS.md archive (resolved incidents)
/sic grade <title> <desc>    # AI-grade a security finding
```

## Implementation

Use $ARGUMENTS to determine the command. All endpoints hit `http://127.0.0.1:9888`.

**health (default, empty args):**
```
curl -s http://127.0.0.1:9888/health | python3 -m json.tool
```

**scan <type> — web | recon | network | full:**
```
curl -s -X POST http://127.0.0.1:9888/api/intelligence/smart-scan \
  -H "Content-Type: application/json" \
  -d "{\"scan_type\": \"<type>\"}" | python3 -m json.tool
```

**incidents:**
```
curl -s http://127.0.0.1:9888/api/incidents | python3 -m json.tool
```

**incident <id>:**
```
curl -s http://127.0.0.1:9888/api/incidents/<id> | python3 -m json.tool
```

**fix <finding-id>:**
```
curl -s -X POST http://127.0.0.1:9888/api/command \
  -H "Content-Type: application/json" \
  -d "{\"command\": \"fix\", \"finding_id\": \"<finding-id>\"}" | python3 -m json.tool
```

**export <scan-id> [format]:**
```
curl -s "http://127.0.0.1:9888/api/export/<scan-id>?format=json" | python3 -m json.tool
```

**bugs:**
```
curl -s http://127.0.0.1:9888/api/bugs-archive | python3 -m json.tool
```

**grade <title> <desc>:**
```
curl -s -X POST http://127.0.0.1:9888/api/ai/grade \
  -H "Content-Type: application/json" \
  -d "{\"title\": \"<title>\", \"description\": \"<desc>\"}" | python3 -m json.tool
```

## Notes

- SIC server must be running: `cd sic && python server.py`
- PDF export requires team/studio tier and WeasyPrint installed (`pip install weasyprint`)
- AI grading requires `OPENROUTER_API_KEY` or `ANTHROPIC_API_KEY` in environment
- Default port: 9888 (override with `SIC_PORT` env var)
