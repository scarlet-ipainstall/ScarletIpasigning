# Scarlet IPA Signer

A small web interface and backend for re-signing iOS `.ipa` files with a user's own `.p12` certificate and `.mobileprovision` profile.

## Important

GitHub Pages is static hosting, so it cannot execute the signing backend. This repository contains both pieces: the web UI and a Dockerized backend. Deploy the repository to a server/container platform that supports Node.js and Docker, then open that deployment URL.

The signing engine is [zsign](https://github.com/zhlynn/zsign), which supports IPA re-signing on Linux without Xcode or macOS. The server uses temporary files and deletes the uploaded certificate, profile, and IPA after the signing request. Signed IPA downloads expire after 15 minutes or are deleted after download.

## Deploy

1. Build the Docker image from this repository.
2. Run it with port `3000` exposed.
3. Set `PUBLIC_BASE_URL` to the public HTTPS URL of the deployment, for example `https://signer.example.com`.
4. Open the public URL and upload an IPA, P12, provisioning profile, and P12 password.

Example:

```bash
docker build -t scarlet-ipa-signer .
docker run --rm -p 3000:3000 -e PUBLIC_BASE_URL=https://your-domain.example scarlet-ipa-signer
```

For production, put the service behind HTTPS and authentication/rate limiting. Do not commit `.p12`, `.pfx`, `.mobileprovision`, passwords, signed IPAs, or private keys to this repository.

## What it does

- Accepts an IPA, P12, and provisioning profile.
- Passes the P12 password to zsign without storing it in the repository.
- Re-signs the IPA with `zsign -f` by default.
- Returns a temporary download URL for the signed IPA.
- Deletes temporary signing inputs after the request.
- Deletes the signed IPA after 15 minutes or after download.

## Limitations

A provisioning profile and certificate still need to be valid for the app and device(s) being targeted. This project does not bypass Apple's signing, provisioning, certificate, or device restrictions.
