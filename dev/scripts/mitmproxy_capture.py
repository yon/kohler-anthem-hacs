"""
mitmproxy addon to capture Kohler API traffic.

Usage:
    ~/Library/Python/3.9/bin/mitmdump -s dev/scripts/mitmproxy_capture.py -w dev/output/mitmproxy_capture.flow

Or with mitmweb for interactive viewing:
    ~/Library/Python/3.9/bin/mitmweb -s dev/scripts/mitmproxy_capture.py
"""

import json
from datetime import datetime
from mitmproxy import http, ctx

# Filter for Kohler API traffic
KOHLER_HOSTS = [
    "api-kohler-us.kohler.io",
    "kohler.io",
    "konnectkohler.b2clogin.com",
    "prd-hub.azure-devices.net",
]

OUTPUT_FILE = "dev/output/mitmproxy_http.log"


class KohlerCapture:
    def __init__(self):
        self.request_count = 0

    def request(self, flow: http.HTTPFlow) -> None:
        """Capture outgoing requests."""
        host = flow.request.host

        # Check if this is Kohler-related traffic
        is_kohler = any(h in host for h in KOHLER_HOSTS)
        if not is_kohler:
            return

        self.request_count += 1
        timestamp = datetime.now().strftime("%H:%M:%S.%f")[:-3]

        # Log to console
        ctx.log.info(f"[{timestamp}] >>> REQUEST #{self.request_count}")
        ctx.log.info(f"    {flow.request.method} {flow.request.pretty_url}")

        # Log headers
        ctx.log.info("    Headers:")
        for k, v in flow.request.headers.items():
            # Truncate long values
            display_v = v[:80] + "..." if len(v) > 80 else v
            ctx.log.info(f"      {k}: {display_v}")

        # Log body
        if flow.request.content:
            try:
                body = json.loads(flow.request.content)
                ctx.log.info(f"    Body: {json.dumps(body, indent=2)}")
            except:
                ctx.log.info(f"    Body: {flow.request.content[:500]}")

        # Write to file
        self._write_to_file(flow, "REQUEST")

    def response(self, flow: http.HTTPFlow) -> None:
        """Capture responses."""
        host = flow.request.host

        is_kohler = any(h in host for h in KOHLER_HOSTS)
        if not is_kohler:
            return

        timestamp = datetime.now().strftime("%H:%M:%S.%f")[:-3]

        ctx.log.info(f"[{timestamp}] <<< RESPONSE {flow.response.status_code}")

        if flow.response.content:
            try:
                body = json.loads(flow.response.content)
                ctx.log.info(f"    Body: {json.dumps(body, indent=2)}")
            except:
                content = flow.response.content[:500]
                ctx.log.info(f"    Body: {content}")

        self._write_to_file(flow, "RESPONSE")

    def _write_to_file(self, flow: http.HTTPFlow, direction: str):
        """Write captured traffic to log file."""
        timestamp = datetime.now().isoformat()

        with open(OUTPUT_FILE, "a") as f:
            f.write(f"\n{'='*80}\n")
            f.write(f"[{timestamp}] {direction}\n")
            f.write(f"{'='*80}\n")

            if direction == "REQUEST":
                f.write(f"Method: {flow.request.method}\n")
                f.write(f"URL: {flow.request.pretty_url}\n")
                f.write(f"\nHeaders:\n")
                for k, v in flow.request.headers.items():
                    f.write(f"  {k}: {v}\n")
                if flow.request.content:
                    f.write(f"\nBody:\n")
                    try:
                        body = json.loads(flow.request.content)
                        f.write(json.dumps(body, indent=2))
                    except:
                        f.write(str(flow.request.content))
                    f.write("\n")
            else:
                f.write(f"Status: {flow.response.status_code}\n")
                f.write(f"\nHeaders:\n")
                for k, v in flow.response.headers.items():
                    f.write(f"  {k}: {v}\n")
                if flow.response.content:
                    f.write(f"\nBody:\n")
                    try:
                        body = json.loads(flow.response.content)
                        f.write(json.dumps(body, indent=2))
                    except:
                        f.write(str(flow.response.content[:2000]))
                    f.write("\n")


addons = [KohlerCapture()]
