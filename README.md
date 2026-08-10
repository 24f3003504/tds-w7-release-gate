# release-gate

Deterministic policy endpoint: `POST /release-gate`

## Files
- `server.js` — Express app + pure `evaluate()` policy function
- `package.json`
- `test/tests.js` — 21 unit tests covering every violation code and combos
- `.github/workflows/release-gate.yml` — required CI evidence workflow

## Run locally
```
npm install
npm start          # serves on http://localhost:3000/release-gate
npm test           # runs the unit test suite
```

## Deploy (pick one, both have free tiers)

### Option A: Render.com
1. Push this repo to GitHub (public).
2. Go to render.com → New → Web Service → connect your repo.
3. Build command: `npm install`
4. Start command: `npm start`
5. Deploy. You'll get a URL like `https://release-gate-xxxx.onrender.com`.
6. Your endpoint is `https://release-gate-xxxx.onrender.com/release-gate`.

### Option B: Railway.app
1. Push this repo to GitHub (public).
2. railway.app → New Project → Deploy from GitHub repo.
3. Railway auto-detects Node, runs `npm install` + `npm start`.
4. Generate a public domain under Settings → Networking.

## GitHub setup (do this in your own repo)
1. Create a new **public** GitHub repository.
2. Copy all files from this folder into the repo root (keep the `.github/workflows/release-gate.yml` path exactly).
3. Commit and push directly to `main` (or open a PR and merge to `main`).
   - The workflow only triggers on push to `main`, so the evidence run must land there.
4. Go to the repo's **Actions** tab and confirm a run named **TDS GA7 Release Gate** completed successfully, with a step named exactly **TDS identity: 24f3003504@ds.study.iitm.ac.in**.
5. Copy the **workflow page URL** — it looks like:
   `https://github.com/<you>/<repo>/actions/workflows/release-gate.yml`
   (not a specific run URL).

## Submission JSON
```json
{
  "endpoint": "https://<your-deployed-app>/release-gate",
  "repo": "https://github.com/<you>/<repo>",
  "workflow": "https://github.com/<you>/<repo>/actions/workflows/release-gate.yml"
}
```
(Match field names to whatever the grader's submission form actually asks for — the important parts are the live endpoint URL and the workflow page URL.)
