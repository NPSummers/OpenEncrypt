from pathlib import Path
import os
import sys

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from LibreMessenger.app import create_app

app = create_app()

if __name__ == "__main__":
    port = int(os.environ.get("LIBREMESSENGER_PORT", "8000"))
    app.run(host="127.0.0.1", port=port, debug=True)

