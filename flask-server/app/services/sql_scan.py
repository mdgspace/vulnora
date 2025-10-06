import subprocess
import tempfile
import os
import logging
import json

logger = logging.getLogger(__name__)

def run_sqlmap(target_url, timeout_seconds=300):
    try:
        with tempfile.TemporaryDirectory() as tmpdir:
            report_path = os.path.join(tmpdir, "sqlmap_report.txt")
            command = [
                "sqlmap",
                "-u", target_url,
                "--batch",
                "--crawl=3",
                "--random-agent",
                "--threads=5",
                "--risk=2",
                "--output-dir", tmpdir
            ]

            process = subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                encoding="utf-8",
                errors="replace"
            )

            try:
                stdout, stderr = process.communicate(timeout=timeout_seconds)
            except subprocess.TimeoutExpired:
                process.kill()
                return {"status": "error", "error": "SQLMap scan timed out"}

            output = (stdout or "") + "\n" + (stderr or "")
            output_lower = output.lower()

            if ("no parameter(s) found for testing" in output_lower) or ("no usable links found" in output_lower):
                result = "NO VULNERABILITIES FOUND"
            else:
                result = "THERE ARE VULNERABILITIES"

            return {
                "status": "completed",
                "result": result,
                "response": output.strip()
            }

    except Exception as e:
        logger.error(f"SQLMap run failed: {e}")
        return {"error": str(e), "status": "error"}
