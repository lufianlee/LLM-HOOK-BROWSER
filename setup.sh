#!/bin/bash
set -e

echo "=== LLM Security Proxy Setup ==="

if ! command -v python3 &> /dev/null; then
    echo "Error: python3 not found"
    exit 1
fi

echo "[1/4] Creating virtual environment..."
python3 -m venv venv
source venv/bin/activate

echo "[2/4] Installing dependencies..."
pip install -r requirements.txt

echo "[3/4] Setting up .env..."
if [ ! -f .env ]; then
    cp .env.example .env
    echo "  Created .env from .env.example - please edit with your credentials"
else
    echo "  .env already exists, skipping"
fi

echo "[4/4] Done!"
echo ""
echo "=== Next Steps ==="
echo "1. Edit .env with your AWS Bedrock credentials (or set LLM_PROVIDER=anthropic)"
echo "2. Set TARGET_DOMAINS to the domains you want to monitor"
echo "3. Run: source venv/bin/activate && python main.py"
echo "4. Configure browser proxy to 127.0.0.1:8080"
echo "5. Open http://127.0.0.1:8000 for the dashboard"
echo ""
echo "For HTTPS traffic, install the mitmproxy CA certificate:"
echo "  - Start the proxy, then visit http://mitm.it in your browser"
