const express = require('express');
const multer = require('multer');
const fs = require('fs');
const fsp = fs.promises;
const path = require('path');
const os = require('os');
const crypto = require('crypto');
const { spawn, execFile } = require('child_process');
const { promisify } = require('util');
const bplistParser = require('bplist-parser');
const plist = require('plist');

const execFileAsync = promisify(execFile);
const app = express();
const PORT = process.env.PORT || 10000;
const MAX_FILE = 1024 * 1024 * 1024; // 1 GiB
const RETENTION_MS = 15 * 60 * 1000;
const upload = multer({
  dest: os.tmpdir(),
  limits: { fileSize: MAX_FILE, files: 3 }
});

app.set('trust proxy', 1);
app.use(express.static(path.join(__dirname)));
app.get('/health', (_req, res) => res.json({ ok: true }));

function runZsign(args, cwd) {
  return new Promise((resolve, reject) => {
    const child = spawn(process.env.ZSIGN_PATH || '/opt/zsign/zsign', args, {
      cwd,
      stdio: ['ignore', 'pipe', 'pipe']
    });
    let stdout = '', stderr = '';
    child.stdout.on('data', d => stdout += d);
    child.stderr.on('data', d => stderr += d);
    child.on('error', reject);
    child.on('close', code => code === 0
      ? resolve({ stdout, stderr })
      : reject(new Error((stderr || stdout || `zsign exited with ${code}`).slice(-5000))));
  });
}

async function removeTree(dir) {
  try { await fsp.rm(dir, { recursive: true, force: true }); } catch {}
}

function safeName(name, fallback) {
  return path.basename(name || fallback).replace(/[^a-zA-Z0-9._-]/g, '_');
}

function safeId(id) {
  return /^[a-f0-9]{36}$/.test(id);
}

function xmlEscape(value) {
  return String(value ?? '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&apos;');
}

async function readAppInfo(ipaPath) {
  const listing = await execFileAsync('unzip', ['-Z1', ipaPath], { maxBuffer: 4 * 1024 * 1024 });
  const infoPath = String(listing.stdout).split(/\r?\n/).find(p => /^Payload\/[^/]+\.app\/Info\.plist$/.test(p));
  if (!infoPath) throw new Error('Could not find Payload/*.app/Info.plist inside the IPA.');

  const extracted = await execFileAsync('unzip', ['-p', ipaPath, infoPath], {
    encoding: 'buffer',
    maxBuffer: 10 * 1024 * 1024
  });
  const buffer = Buffer.isBuffer(extracted.stdout) ? extracted.stdout : Buffer.from(extracted.stdout);
  let info;
  if (buffer.subarray(0, 6).toString() === 'bplist') {
    info = bplistParser.parseBuffer(buffer)[0];
  } else {
    info = plist.parse(buffer.toString('utf8'));
  }

  const bundleId = info.CFBundleIdentifier;
  if (!bundleId) throw new Error('The IPA does not contain a CFBundleIdentifier.');
  return {
    bundleIdentifier: String(bundleId),
    bundleVersion: String(info.CFBundleShortVersionString || info.CFBundleVersion || '1.0'),
    title: String(info.CFBundleDisplayName || info.CFBundleName || bundleId)
  };
}

function manifestXml(meta, ipaUrl) {
  return `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>items</key><array><dict>
<key>assets</key><array><dict>
<key>kind</key><string>software-package</string>
<key>url</key><string>${xmlEscape(ipaUrl)}</string>
</dict></array>
<key>metadata</key><dict>
<key>bundle-identifier</key><string>${xmlEscape(meta.bundleIdentifier)}</string>
<key>bundle-version</key><string>${xmlEscape(meta.bundleVersion)}</string>
<key>kind</key><string>software</string>
<key>title</key><string>${xmlEscape(meta.title)}</string>
</dict>
</dict></array>
</dict></plist>`;
}

app.post('/api/sign', upload.fields([
  { name: 'ipa', maxCount: 1 },
  { name: 'p12', maxCount: 1 },
  { name: 'prov', maxCount: 1 }
]), async (req, res) => {
  const files = req.files || {};
  if (!files.ipa?.[0] || !files.p12?.[0] || !files.prov?.[0]) {
    return res.status(400).json({ error: 'IPA, P12, and provisioning profile are required.' });
  }
  const password = String(req.body.password || '');
  if (!password) return res.status(400).json({ error: 'P12 password is required.' });

  const jobId = crypto.randomBytes(18).toString('hex');
  const work = path.join(os.tmpdir(), `scarlet-sign-${jobId}`);
  const outDir = path.join(os.tmpdir(), 'scarlet-signed');
  await fsp.mkdir(work, { recursive: true });
  await fsp.mkdir(outDir, { recursive: true });
  const ipa = path.join(work, safeName(files.ipa[0].originalname, 'input.ipa'));
  const p12 = path.join(work, safeName(files.p12[0].originalname, 'certificate.p12'));
  const prov = path.join(work, safeName(files.prov[0].originalname, 'profile.mobileprovision'));
  const output = path.join(outDir, `${jobId}-signed.ipa`);
  const metadataFile = path.join(outDir, `${jobId}.json`);
  const cleanupInputs = async () => { await removeTree(work); };

  try {
    await fsp.rename(files.ipa[0].path, ipa);
    await fsp.rename(files.p12[0].path, p12);
    await fsp.rename(files.prov[0].path, prov);

    const args = ['-k', p12, '-p', password, '-m', prov, '-o', output, '-z', '9'];
    if (String(req.body.force) !== 'false') args.push('-f');
    args.push(ipa);
    await runZsign(args, work);

    const meta = await readAppInfo(output);
    await fsp.writeFile(metadataFile, JSON.stringify(meta), 'utf8');
    await cleanupInputs();

    const base = `${req.protocol}://${req.get('host')}`;
    res.json({
      ok: true,
      message: 'IPA signed successfully.',
      filename: 'signed.ipa',
      downloadUrl: `${base}/download/${jobId}`,
      manifestUrl: `${base}/manifest/${jobId}.plist`,
      installUrl: `itms-services://?action=download-manifest&url=${encodeURIComponent(`${base}/manifest/${jobId}.plist`)}`
    });

    setTimeout(async () => {
      try { await fsp.unlink(output); } catch {}
      try { await fsp.unlink(metadataFile); } catch {}
    }, RETENTION_MS);
  } catch (err) {
    await cleanupInputs();
    try { await fsp.unlink(output); } catch {}
    try { await fsp.unlink(metadataFile); } catch {}
    res.status(500).json({ error: `Signing failed: ${err.message}` });
  }
});

app.get('/download/:id', async (req, res) => {
  if (!safeId(req.params.id)) return res.status(400).send('Invalid download id');
  const file = path.join(os.tmpdir(), 'scarlet-signed', `${req.params.id}-signed.ipa`);
  try {
    await fsp.access(file);
    res.download(file, 'signed.ipa', async () => {
      try { await fsp.unlink(file); } catch {}
      try { await fsp.unlink(path.join(os.tmpdir(), 'scarlet-signed', `${req.params.id}.json`)); } catch {}
    });
  } catch {
    res.status(404).send('This signed IPA has expired or does not exist.');
  }
});

app.get('/manifest/:id.plist', async (req, res) => {
  if (!safeId(req.params.id)) return res.status(400).type('text/plain').send('Invalid manifest id');
  const dir = path.join(os.tmpdir(), 'scarlet-signed');
  const file = path.join(dir, `${req.params.id}-signed.ipa`);
  const metadataFile = path.join(dir, `${req.params.id}.json`);
  try {
    await fsp.access(file);
    const meta = JSON.parse(await fsp.readFile(metadataFile, 'utf8'));
    const base = `${req.protocol}://${req.get('host')}`;
    const xml = manifestXml(meta, `${base}/download/${req.params.id}`);
    res.type('application/xml').send(xml);
  } catch {
    res.status(404).type('text/plain').send('This manifest has expired or does not exist.');
  }
});

app.use((err, _req, res, _next) => {
  if (err?.code === 'LIMIT_FILE_SIZE') return res.status(413).json({ error: 'A file is larger than the 1 GiB limit.' });
  res.status(500).json({ error: 'Unexpected server error.' });
});

app.listen(PORT, () => console.log(`Scarlet IPA Signer listening on ${PORT}`));
