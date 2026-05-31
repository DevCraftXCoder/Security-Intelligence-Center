#!/usr/bin/env python3
"""SIC Installation Audit — checks your SIC install is configured correctly."""
import os, sys, subprocess, urllib.request, urllib.error

def check(label, result, fix=None):
    icon = "✓" if result else "✗"
    print(f"  {icon}  {label}")
    if not result and fix:
        print(f"     → {fix}")
    return result

print("\n=== SIC Installation Audit ===\n")
env = {}
if os.path.exists(".env"):
    with open(".env") as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, _, v = line.partition("=")
                env[k.strip()] = v.strip()

# Load real env too
env.update(os.environ)

results = []
results.append(check("Python >= 3.8", sys.version_info >= (3, 8), "Upgrade Python"))
results.append(check("SIC_SECRET_KEY set", bool(env.get("SIC_SECRET_KEY")), "Set SIC_SECRET_KEY in .env"))
results.append(check("SIC_ADMIN_EMAILS set", bool(env.get("SIC_ADMIN_EMAILS")), "Set SIC_ADMIN_EMAILS=your@email.com in .env"))
results.append(check("STRIPE_SECRET_KEY set", bool(env.get("STRIPE_SECRET_KEY")), "Set STRIPE_SECRET_KEY in .env"))
results.append(check("STRIPE_PRICE_TEAM set", bool(env.get("STRIPE_PRICE_TEAM", "").replace("your_stripe_team_price_id", "")), "Create a Stripe Price and set STRIPE_PRICE_TEAM"))
results.append(check("STRIPE_PRICE_STUDIO set", bool(env.get("STRIPE_PRICE_STUDIO", "").replace("your_stripe_studio_price_id", "")), "Create a Stripe Price and set STRIPE_PRICE_STUDIO"))
results.append(check("BILLING_API_KEY set", bool(env.get("BILLING_API_KEY")), "Set BILLING_API_KEY in .env"))

base_url = env.get("SIC_BASE_URL", "http://localhost:9888")
is_localhost = "localhost" in base_url or "127.0.0.1" in base_url
results.append(check(
    "SIC_BASE_URL is public (required for email links)",
    not is_localhost,
    f"Set SIC_BASE_URL to your public server URL -- currently '{base_url}' (localhost links won't work in emails)"
))

port = env.get("SIC_PORT", "9888")
try:
    urllib.request.urlopen(f"http://localhost:{port}/health", timeout=3)
    results.append(check(f"SIC server reachable (:{port})", True))
except:
    results.append(check(f"SIC server reachable (:{port})", False, "Run: python server.py"))

billing_port = env.get("BILLING_PORT", "9015")
try:
    urllib.request.urlopen(f"http://localhost:{billing_port}/health", timeout=3)
    results.append(check(f"Billing server reachable (:{billing_port})", True))
except:
    results.append(check(f"Billing server reachable (:{billing_port})", False, "Run: python billing_server.py"))

results.append(check("logs/ directory writable", os.access("logs", os.W_OK) or not os.path.exists("logs"), "Run: mkdir logs"))

passed = sum(1 for r in results if r)
total = len(results)
score = int(passed / total * 100)
print(f"\nScore: {score}/100 ({passed}/{total} checks passed)\n")
if score == 100:
    print("✓ SIC is ready.\n")
elif score >= 70:
    print("⚠ SIC is partially configured. Fix warnings above before taking payments.\n")
else:
    print("✗ SIC has critical gaps. Do not accept payments until resolved.\n")
