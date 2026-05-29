# SIC Production Runbook

> HexStrike AI Tools API Server — operational reference for production deployments.

## Required Environment Variables

| Variable | Required in prod | Default | Notes |
|----------|-----------------|---------|-------|
| `SIC_SECRET_KEY` | YES | random (ephemeral) | Flask session key — set to a 32+ char secret |
| `SIC_IP_ALLOWLIST` | YES | `127.0.0.1/8,::1` | Must be non-default in production |
| `SIC_ENV` | YES | `development` | Set to `production` to activate hardening |
| `SIC_COMMAND_ALLOWLIST` | YES (if /api/command used) | — | Comma-separated allowed binary names |
| `SIC_MAX_REQUEST_BYTES` | NO | `10485760` (10 MiB) | Max request body size |
| `SIC_PORT` | NO | `9888` | API server port |
| `SIC_HOST` | NO | `127.0.0.1` | Bind address |

## Production Boot Checklist

1. Set `SIC_ENV=production`
2. Set `SIC_SECRET_KEY` to a 32+ char random value (`python -c "import secrets; print(secrets.token_hex(32))"`)
3. Set `SIC_IP_ALLOWLIST` to your home network CIDR (e.g. `192.168.1.0/24,10.0.0.1/32`)
4. Set `SIC_COMMAND_ALLOWLIST` to the binaries you permit (e.g. `nmap,gobuster,nuclei,nikto`)
5. Verify boot: `python server.py` — if env vars are missing, server will print FATAL and exit
6. Confirm health: `curl http://127.0.0.1:9888/health`

## Audit Logs

All `/api/command` invocations are logged to `logs/audit/YYYY-MM-DD.jsonl`.

```bash
# View today's audit entries
cat logs/audit/$(date +%Y-%m-%d).jsonl | python -m json.tool

# Search for a specific command
grep '"event":"command_executed"' logs/audit/$(date +%Y-%m-%d).jsonl
```

Log entries include: timestamp, event name, command string.

## Rate Limits

Default: 200 requests/minute per IP (all routes).
`/api/command`: 60 requests/minute per IP.
`/api/admin/panic-stop`: 3 requests/minute per IP.

## Panic Stop

Emergency server shutdown endpoint. Only available when `SIC_ENV=production`.

```bash
# Trigger panic stop (requires authenticated session cookie)
curl -X POST http://127.0.0.1:9888/api/admin/panic-stop \
  -H "Cookie: session=<your-session-cookie>"
```

The server sends itself `SIGTERM` and exits cleanly. Use PM2 or systemd to auto-restart if needed.

## Restarting

```bash
pm2 restart sic          # if managed by PM2
python server.py  # manual
```

## Checking Logs

```bash
pm2 logs sic             # PM2 managed
tail -f logs/audit/$(date +%Y-%m-%d).jsonl  # audit stream
```
