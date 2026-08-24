# Scarlet IPA Signer

A small web interface and backend for re-signing iOS `.ipa` files with a user's own `.p12` certificate and `.mobileprovision` profile.

## Important

GitHub Pages is static hosting, so it cannot execute the signing backend. This repository contains both pieces: the web UI and a Dockerized backend. Deploy the repository to a server/container platform that supports Node.js and Docker.

The signing engine is [zsign](https://github.com/zhlynn/zsign), which supports IPA re-signing on Linux without Xcode or macOS. Signing inputs are temporary. Signed IPAs and manifests can be stored persistently in Cloudflare R2 so a generated direct-install link can be reused.

## Cloudflare R2 persistent storage

Create an R2 bucket and an R2 API token with **Object Read & Write** permission scoped only to that bucket. Cloudflare's S3-compatible endpoint is `https://<ACCOUNT_ID>.r2.cloudflarestorage.com`. Enable public read access for the bucket or attach a public custom domain, then use that public base URL for `R2_PUBLIC_BASE_URL`.

Set these environment variables in Render (never commit them to GitHub):

- `R2_ACCOUNT_ID` — your Cloudflare account ID.
- `R2_ACCESS_KEY_ID` — R2 API token access key.
- `R2_SECRET_ACCESS_KEY` — R2 API token secret.
- `R2_BUCKET_NAME` — the R2 bucket name.
- `R2_PUBLIC_BASE_URL` — the HTTPS public URL that serves objects from the bucket, without a trailing slash.

The server uploads the signed IPA and `manifest.plist` to R2 and returns an `itms-services://` link. Because the objects are public and are not given an expiration time, the link remains reusable until the objects are removed or the public URL is changed.

## Deploy

1. Deploy this repository as a Docker Web Service on Render.
2. Keep the service on the `main` branch and use the included `Dockerfile`.
3. Add the five R2 environment variables above in Render.
4. Redeploy.
5. Open the service URL and upload an IPA, P12, provisioning profile, and P12 password.

Cloudflare documents the R2 S3 API and API-token setup here: https://developers.cloudflare.com/r2/get-started/s3/

## Security

Do not commit `.p12`, `.pfx`, `.mobileprovision`, passwords, signed IPAs, or Cloudflare API secrets to this repository. Treat R2 API secrets as credentials and scope the token to only the required bucket. If the public bucket contains an IPA, anyone who knows its URL can download it.

For production, consider authentication/rate limiting on the signer and a lifecycle policy for old signed IPAs.

## What it does

- Accepts an IPA, P12, and provisioning profile.
- Passes the P12 password to zsign without storing it in the repository.
- Re-signs the IPA with `zsign -f` by default.
- Uploads the signed IPA to R2.
- Generates a reusable `manifest.plist` in R2.
- Generates an `itms-services://` direct-install URL.
- Deletes temporary signing inputs from the Render filesystem after the request.

## Limitations

A provisioning profile and certificate still need to be valid for the app and device(s) being targeted. This project does not bypass Apple's signing, provisioning, certificate, or device restrictions.
