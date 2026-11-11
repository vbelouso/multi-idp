"""Exercise dashboard generation without cluster access or credentials."""
import json
import os
import re
import shutil
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


SCRIPT = Path(__file__).resolve().parents[1] / "generate_dashboard.py"


def audit(run="example", **changes):
    result = {
        "runId": run, "utc": "2026-11-11T12:00:00+00:00",
        "installations": {}, "tests": {"N8": {
            "name": "B rejects an unapproved client", "status": "fail",
            "description": "The resource server accepted an unapproved client.",
        }}, "milestones": {}, "complete": False,
        "resetValidation": "not-run",
    }
    result.update(changes)
    return result


class DashboardTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.evidence = self.root / "evidence"
        self.evidence.mkdir()

    def run_generator(self, *args):
        return subprocess.run(
            [sys.executable, str(SCRIPT), *map(str, args)],
            cwd=self.root, capture_output=True, text=True,
        )

    def write_audit(self, name, data):
        path = self.evidence / name
        path.write_text(json.dumps(data))
        return path

    def test_selects_newest_audit_and_keeps_source_unchanged(self):
        old = self.write_audit("audit-old.json", audit("old"))
        latest = self.write_audit("audit-latest.json", audit("latest"))
        self.write_audit("installation.json", {})
        os.utime(old, ns=(1, 1))
        before = latest.read_bytes()
        result = self.run_generator("--evidence-dir", self.evidence)
        self.assertEqual(result.returncode, 0, result.stderr)
        output = self.evidence / "dashboards/audit-latest.html"
        self.assertTrue(output.is_file(), result.stdout)
        self.assertEqual(latest.read_bytes(), before)
        self.assertIn('"runId":"latest"', output.read_text())

    def test_custom_audit_and_output_embed_safe_payload(self):
        source = self.write_audit("custom.json", audit("</script><script>alert(1)</script>"))
        output = self.root / "reports/custom.html"
        result = self.run_generator(source, "-o", output)
        self.assertEqual(result.returncode, 0, result.stderr)
        html = output.read_text()
        self.assertNotIn('</script><script>alert(1)', html)
        payload = html.split('<script id="payload" type="application/json">', 1)[1].split('</script>', 1)[0]
        self.assertEqual(json.loads(payload)["audit"]["runId"], "</script><script>alert(1)</script>")

    def test_no_audit_gives_actionable_error(self):
        result = self.run_generator("--evidence-dir", self.evidence)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("No audit-*.json", result.stderr)
        self.assertFalse((self.evidence / "dashboards").exists())

    def test_rejects_wrong_report_shape_without_traceback(self):
        for data in ([], audit(tests=[]), audit(milestones={"M1": {"requiredTests": "N8"}}), audit(extra=float('nan'))):
            with self.subTest(data=data):
                source = self.write_audit("bad.json", data)
                result = self.run_generator(source)
                self.assertNotEqual(result.returncode, 0)
                self.assertNotIn("Traceback", result.stderr)

    def test_output_cannot_overwrite_audit(self):
        source = self.write_audit("audit-source.json", audit())
        before = source.read_bytes()
        result = self.run_generator(source, "-o", source)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(source.read_bytes(), before)

    @unittest.skipUnless(shutil.which("google-chrome"), "Chrome is required for browser checks")
    def test_browser_filters_statuses_tokens_and_custom_file_loading(self):
        data = audit(tests={
            "P1": {"name": "Internal token", "status": "pass", "t1": {
                "subjectLabel": "Internal pilot user", "azp": "agent-a-internal",
                "issuer": "https://issuer.example/realms/internal", "audience": ["agent-c"],
            }},
            "N8": {"name": "Unapproved client", "status": "fail"},
        }, milestones={"M1": {"name": "Authorization", "status": "fail", "requiredTests": ["P1", "N8"]}})
        source = self.write_audit("audit-browser.json", data)
        output = self.root / "browser.html"
        result = self.run_generator(source, "-o", output)
        self.assertEqual(result.returncode, 0, result.stderr)
        script = r'''<script>
        (async () => {
          const result = document.createElement('pre'); result.id = 'browser-result';
          const check = (condition, message) => { if (!condition) throw Error(message); };
          const load = async (data, name) => {
            const input = document.getElementById('audit-file'), transfer = new DataTransfer();
            transfer.items.add(new File([JSON.stringify(data)], name, {type: 'application/json'}));
            input.files = transfer.files;
            await new Promise(resolve => {
              const observer = new MutationObserver(() => { observer.disconnect(); resolve(); });
              observer.observe(document.getElementById('source'), {childList: true});
              observer.observe(document.getElementById('load-error'), {childList: true, attributes: true});
              input.dispatchEvent(new Event('change'));
            });
          };
          try {
            check(document.getElementById('testscore').textContent === '1 / 2', 'Dynamic test count');
            check(document.getElementById('testscore').classList.contains('bad'), 'Failed summary styling');
            check(document.getElementById('milestone-status').classList.contains('failure'), 'Failed milestone summary styling');
            check(document.querySelectorAll('#test-rows .bad').length === 1, 'Failed table row styling');
            check(document.querySelector('#test-list .bad').textContent === 'fail', 'Failed evidence status');
            check(document.getElementById('token-detail').textContent.includes('Internal pilot user'), 'Readable subject');
            check(document.getElementById('token-detail').textContent.includes('agent-a-internal'), 'Client separate from user');
            document.querySelector('[data-view="tests"]').click();
            document.querySelector('[data-filter="N"]').click();
            check(document.querySelectorAll('#test-rows tr').length === 1, 'Negative test filter');
            document.querySelector('.testlink').click();
            check(document.getElementById('evidence').classList.contains('active'), 'Evidence tab navigation');
            const search = document.getElementById('search'); search.value = 'no such test'; search.dispatchEvent(new Event('input'));
            check(document.getElementById('detail').textContent.includes('No matching tests'), 'Empty search clears stale detail');
            await load({runId: 'custom', utc: 'now', installations: {}, milestones: {},
              tests: {N99: {name: '<img src=x onerror=alert(1)>', status: 'pass'}}}, 'custom.json');
            check(document.getElementById('source').textContent.includes('custom.json'), 'Custom file source');
            check(document.getElementById('testscore').textContent === '1 / 1', 'Custom file replaces counts');
            check(document.getElementById('complete').textContent === 'Not recorded', 'Absent completion is not success');
            check(document.querySelectorAll('#test-rows tr').length === 1, 'Custom file clears old rows and filters');
            check(!document.querySelector('#test-rows img'), 'Custom text rendered safely');
            check(document.getElementById('token-detail').textContent.includes('does not record'), 'Missing tokens explicit');
            await load([], 'invalid.json');
            check(!document.getElementById('load-error').hidden, 'Invalid file error');
            check(document.getElementById('testscore').textContent === '1 / 1', 'Invalid file preserves valid report');
            await load({runId: 'empty', utc: 'now', installations: {}, milestones: {}, tests: {}}, 'empty.json');
            check(document.getElementById('testscore').textContent === '0 / 0', 'Empty audit handled');
            check(document.getElementById('testscore').classList.contains('warn'), 'Empty audit not green');
            result.textContent = 'PASS';
          } catch (error) { result.textContent = 'FAIL: ' + error.message; }
          document.body.append(result);
        })();
        </script>'''
        output.write_text(output.read_text().replace('</body>', script + '</body>'))
        browser = subprocess.run([
            shutil.which('google-chrome'), '--headless', '--no-sandbox', '--disable-gpu',
            '--disable-background-networking', '--no-first-run', '--no-default-browser-check',
            '--user-data-dir=' + str(self.root / 'chrome'), '--virtual-time-budget=3000',
            '--dump-dom', output.as_uri(),
        ], capture_output=True, text=True, timeout=30)
        self.assertEqual(browser.returncode, 0, browser.stderr[-2000:])
        marker = re.search(r'<pre id="browser-result">(.*?)</pre>', browser.stdout, re.S)
        self.assertIsNotNone(marker, browser.stderr[-2000:])
        self.assertEqual(marker.group(1), 'PASS')


if __name__ == "__main__":
    unittest.main()
