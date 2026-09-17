"""Check the small, prebuilt-binary-only public image context contract."""
from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[1]

class ImageContractTests(unittest.TestCase):
    def test_runtime_is_pinned_and_uses_only_the_target_binary(self):
        dockerfile = ROOT / 'Dockerfile'
        self.assertTrue(dockerfile.is_file(), 'Dockerfile is missing')
        text = dockerfile.read_text()
        self.assertRegex(text, r'(?m)^FROM gcr\.io/distroless/static-debian12@sha256:[0-9a-f]{64}$')
        self.assertEqual(re.findall(r'(?m)^COPY .+$', text), ['COPY dist/linux/${TARGETARCH}/agentkubenetwork /usr/local/bin/agentkubenetwork'])
        self.assertIn('ENTRYPOINT ["/usr/local/bin/agentkubenetwork"]', text)
        self.assertIn('CMD ["-source=ebpf", "-output-mode=windows", "-export=tagcount"]', text)
        self.assertNotIn('pod-identity=false', text)
        self.assertNotRegex(text, r'(?m)^ENV .*?(?:ACCESSKEY|LICENSE|TOKEN|PASSWORD)')
        ignore = (ROOT / '.dockerignore').read_text().splitlines()
        self.assertEqual(ignore, ['**', '!Dockerfile', '!dist/', '!dist/linux/', '!dist/linux/amd64/', '!dist/linux/amd64/agentkubenetwork', '!dist/linux/arm64/', '!dist/linux/arm64/agentkubenetwork'])

if __name__ == '__main__':
    unittest.main()
