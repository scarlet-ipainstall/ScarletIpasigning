const express = require('express');
const multer = require('multer');
const fs = require('fs');
const fsp = fs.promises;
const path = require('path');
const os = require('os');
const crypto = require('crypto');
const { spawn } = require('child_process');

const app = express();
const PORT = process.env.PORT || 3000;
const MAX_FILE = 1024 * 1024 * 1024; // 1 GiB
const RETENTION_MS = 15 * 60 * 1000;
const PUBLIC_BASE = process.env.PUBLIC_BASE_URL || '';
const upload = multer({
  dest: os.tmpdir(),
  limits: { fileSize: MAX_FILE, files: 3 }
});

app.use(express.static(path.join(__dirname)));
app.get('/health', (_req,res)=>res.json({ok:true}));

function runZsign(args, cwd) {
  return new Promise((resolve,reject)=>{
    const child = spawn(process.env.ZSIGN_PATH || '/opt/zsign/zsign', args, {cwd, stdio:['ignore','pipe','pipe']});
    let stdout='', stderr='';
    child.stdout.on('data',d=>stdout+=d);
    child.stderr.on('data',d=>stderr+=d);
    child.on('error',reject);
    child.on('close',code=>code===0?resolve({stdout,stderr}):reject(new Error((stderr||stdout||`zsign exited with ${code}`).slice(-5000))));
  });
}

async function removeTree(dir){ try{ await fsp.rm(dir,{recursive:true,force:true}); }catch{} }
function safeName(name,fallback){ return path.basename(name||fallback).replace(/[^a-zA-Z0-9._-]/g,'_'); }

app.post('/api/sign', upload.fields([
  {name:'ipa',maxCount:1},
  {name:'p12',maxCount:1},
  {name:'prov',maxCount:1}
]), async (req,res)=>{
  const files=req.files||{};
  if(!files.ipa?.[0]||!files.p12?.[0]||!files.prov?.[0]) return res.status(400).json({error:'IPA, P12, and provisioning profile are required.'});
  const password=String(req.body.password||'');
  if(!password) return res.status(400).json({error:'P12 password is required.'});

  const jobId=crypto.randomBytes(18).toString('hex');
  const work=path.join(os.tmpdir(),`scarlet-sign-${jobId}`);
  const outDir=path.join(os.tmpdir(),'scarlet-signed');
  await fsp.mkdir(work,{recursive:true});
  await fsp.mkdir(outDir,{recursive:true});
  const ipa=path.join(work,safeName(files.ipa[0].originalname,'input.ipa'));
  const p12=path.join(work,safeName(files.p12[0].originalname,'certificate.p12'));
  const prov=path.join(work,safeName(files.prov[0].originalname,'profile.mobileprovision'));
  const output=path.join(outDir,`${jobId}-signed.ipa`);
  const cleanupInputs=async()=>{ await removeTree(work); };
  try{
    await fsp.rename(files.ipa[0].path,ipa);
    await fsp.rename(files.p12[0].path,p12);
    await fsp.rename(files.prov[0].path,prov);
    const args=['-k',p12,'-p',password,'-m',prov,'-o',output,'-z','9'];
    if(String(req.body.force)!=='false') args.push('-f');
    args.push(ipa);
    await runZsign(args,work);
    await cleanupInputs();
    res.json({ok:true,message:'IPA signed successfully.',filename:'signed.ipa',downloadUrl:`${PUBLIC_BASE}/download/${jobId}`});
    setTimeout(async()=>{try{await fsp.unlink(output)}catch{}},RETENTION_MS);
  }catch(err){
    await cleanupInputs();
    try{await fsp.unlink(output)}catch{}
    res.status(500).json({error:`Signing failed: ${err.message}`});
  }
});

app.get('/download/:id',async(req,res)=>{
  if(!/^[a-f0-9]{36}$/.test(req.params.id)) return res.status(400).send('Invalid download id');
  const file=path.join(os.tmpdir(),'scarlet-signed',`${req.params.id}-signed.ipa`);
  try{await fsp.access(file);res.download(file,'signed.ipa',async()=>{try{await fsp.unlink(file)}catch{}})}catch{res.status(404).send('This signed IPA has expired or does not exist.');}
});

app.use((err,_req,res,_next)=>{ if(err?.code==='LIMIT_FILE_SIZE') return res.status(413).json({error:'A file is larger than the 1 GiB limit.'}); res.status(500).json({error:'Unexpected server error.'}); });
app.listen(PORT,()=>console.log(`Scarlet IPA Signer listening on ${PORT}`));
