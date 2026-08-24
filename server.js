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
const admin = require('firebase-admin');

const execFileAsync = promisify(execFile);
const app = express();
const PORT = process.env.PORT || 10000;
const MAX_FILE = 1024 * 1024 * 1024; // 1 GiB
const upload = multer({ dest: os.tmpdir(), limits: { fileSize: MAX_FILE, files: 3 } });

app.set('trust proxy', 1);
app.use(express.static(path.join(__dirname)));
app.get('/health', (_req, res) => res.json({ ok: true, persistentStorage: firebaseReady }));

let bucket = null;
let firebaseReady = false;

function initFirebase() {
  if (firebaseReady) return;
  const json = process.env.FIREBASE_SERVICE_ACCOUNT_JSON;
  const bucketName = process.env.FIREBASE_STORAGE_BUCKET;
  if (!json || !bucketName) return;

  let serviceAccount;
  try {
    serviceAccount = JSON.parse(json);
  } catch (e) {
    throw new Error('FIREBASE_SERVICE_ACCOUNT_JSON is not valid JSON.');
  }

  if (!admin.apps.length) {
    admin.initializeApp({ credential: admin.credential.cert(serviceAccount), storageBucket: bucketName });
  }
  bucket = admin.storage().bucket();
  firebaseReady = true;
}

function requireFirebase() {
  initFirebase();
  if (!firebaseReady) {
    throw new Error('Persistent storage is not configured. Add FIREBASE_SERVICE_ACCOUNT_JSON and FIREBASE_STORAGE_BUCKET in Render Environment Variables.');
  }
}

function firebaseDownloadUrl(objectPath, token) {
  return `https://firebasestorage.googleapis.com/v0/b/${encodeURIComponent(process.env.FIREBASE_STORAGE_BUCKET)}/o/${encodeURIComponent(objectPath)}?alt=media&token=${encodeURIComponent(token)}`;
}

async function uploadPersistent(localPath, objectPath, contentType) {
  requireFirebase();
  const token = crypto.randomUUID();
  const file = bucket.file(objectPath);
  await file.save(await fsp.readFile(localPath), {
    resumable: false,
    metadata: {
      contentType,
      metadata: { firebaseStorageDownloadTokens: token }
    }
  });
  return firebaseDownloadUrl(objectPath, token);
}

async function uploadTextPersistent(text, objectPath, contentType) {
  requireFirebase();
  const token = crypto.randomUUID();
  const file = bucket.file(objectPath);
  await file.save(Buffer.from(text, 'utf8'), {
    resumable: false,
    metadata: {
      contentType,
      metadata: { firebaseStorageDownloadTokens: token }
    }
  });
  return firebaseDownloadUrl(objectPath, token);
}

function runZsign(args, cwd) {
  return new Promise((resolve, reject) => {
    const child = spawn(process.env.ZSIGN_PATH || '/opt/zsign/zsign', args, { cwd, stdio: ['ignore', 'pipe', 'pipe'] });
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

function safeId(id) { return /^[a-f0-9]{36}$/.test(id); }

function xmlEscape(value) {
  return String(value ?? '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&apos;');
}

async function readAppInfo(ipaPath) {
  const listing = await execFileAsync('unzip', ['-Z1', ipaPath], { maxBuffer: 4 * 1024 * 1024 });
  const infoPath = String(listing.stdout).split(/\r?\n/).find(p => /^Payload\/[^/]+\.app\/Info\.plist$/.test(p));
  if (!infoPath) throw new Error('Could not find Payload/*.app/Info.plist inside the IPA.');
  const extracted = await execFileAsync('unzip', ['-p', ipaPath, infoPath], { encoding: 'buffer', maxBuffer: 10 * 1024 * 1024 });
  const buffer = Buffer.isBuffer(extracted.stdout) ? extracted.stdout : Buffer.from(extracted.stdout);
  const info = buffer.subarray(0, 6).toString() === 'bplist' ? bplistParser.parseBuffer(buffer)[0] : plist.parse(buffer.toString('utf8'));
  const bundleId = info.CFBundleIdentifier;
  if (!bundleId) throw new Error('The IPA does not contain a CFBundleIdentifier.');
  return {
    bundleIdentifier: String(bundleId),
    bundleVersion: String(info.CFBundleShortVersionString || info.CFBundleVersion || '1.0'),
    title: String(info.CFBundleDisplayName || info.CFBundleName || bundleId)
  };
}

function manifestXml(meta, ipaUrl) {
  return `<?xml version="1.0" encoding="UTF-8"?>\n<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">\n<plist version="1.0"><dict>\n<key>items</key><array><dict>\n<key>assets</key><array><dict>\n<key>kind</key><string>software-package</string>\n<key>url</key><string>${xmlEscape(ipaUrl)}</string>\n</dict></array>\n<key>metadata</key><dict>\n<key>bundle-identifier</key><string>${xmlEscape(meta.bundleIdentifier)}</string>\n<key>bundle-version</key><string>${xmlEscape(meta.bundleVersion)}</string>\n<key>kind</key><string>software</string>\n<key>title</key><string>${xmlEscape(meta.title)}</string>\n</dict>\n</dict></array>\n</dict></plist>`;
}

app.post('/api/sign', upload.fields([
  { name: 'ipa', maxCount: 1 },
  { name: 'p12', maxCount: 1 },
  { name: 'prov', maxCount: 1 }
]), async (req, res) => {
  const files = req.files || {};
  if (!files.ipa?.[0] || !files.p12?.[0] || !files.prov?.[0]) return res.status(400).json({ error: 'IPA, P12, and provisioning profile are required.' });
  const password = String(req.body.password || '');
  if (!password) return res.status(400).json({ error: 'P12 password is required.' });

  const jobId = crypto.randomUUID();
  const work = path.join(os.tmpdir(), `scarlet-sign-${jobId}`);
  const output = path.join(work, `${jobId}-signed.ipa`);
  await fsp.mkdir(work, { recursive: true });
  const ipa = path.join(work, safeName(files.ipa[0].originalname, 'input.ipa'));
  const p12 = path.join(work, safeName(files.p12[0].originalname, 'certificate.p12'));
  const prov = path.join(work, safeName(files.prov[0].originalname, 'profile.mobileprovision'));

  try {
    await fsp.rename(files.ipa[0].path, ipa);
    await fsp.rename(files.p12[0].path, p12);
    await fsp.rename(files.prov[0].path, prov);

    const args = ['-k', p12, '-p', password, '-m', prov, '-o', output, '-z', '9'];
    if (String(req.body.force) !== 'false') args.push('-f');
    args.push(ipa);
    await runZsign(args, work);

    const meta = await readAppInfo(output);
    requireFirebase();

    const ipaObject = `signed-ipas/${jobId}/${safeName(files.ipa[0].originalname, 'signed')}`;
    const ipaUrl = await uploadPersistent(output, ipaObject, 'application/octet-stream');
    const manifest = manifestXml(meta, ipaUrl);
    const manifestObject = `manifests/${jobId}/manifest.plist`;
    const manifestUrl = await uploadTextPersistent(manifest, manifestObject, 'application/xml');
    const installUrl = `itms-services://?action=download-manifest&url=${encodeURIComponent(manifestUrl)}`;

    await removeTree(work);
    res.json({
      ok: true,
      message: 'IPA signed and permanently uploaded to Firebase Storage.',
      filename: safeName(files.ipa[0].originalname, 'signed.ipa'),
      downloadUrl: ipaUrl,
      manifestUrl,
      installUrl,
      persistent: true
    });
  } catch (err) {
    await removeTree(work);
    res.status(500).json({ error: `Signing failed: ${err.message}` });
  }
});

app.use((err, _req, res, _next) => {
  if (err?.code === 'LIMIT_FILE_SIZE') return res.status(413).json({ error: 'A file is larger than the 1 GiB limit.' });
  res.status(500).json({ error: 'Unexpected server error.' });
});

app.listen(PORT, () => console.log(`Scarlet IPA Signer listening on ${PORT}`));
