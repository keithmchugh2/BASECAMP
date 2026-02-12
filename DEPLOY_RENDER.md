# Deploy BASECAMP On Render

## 1) Put this project in a GitHub repo
- Include:
  - `index.html`
  - `styles.css`
  - `script.js`
  - `server.py`
  - `render.yaml`
- Do not include `.env` (already ignored by `.gitignore`).

## 2) Create the Render web service
- In Render dashboard, click `New +` -> `Blueprint`.
- Connect your GitHub repo and select this project.
- Render will read `render.yaml` and create `basecamp-site`.

## 3) Set secret env var
- In Render service settings, add:
  - `BASECAMP_GMAIL_APP_PASSWORD` = your Gmail app password

## 4) Deploy and test
- Open the Render URL.
- Submit the discovery form.
- Confirm email arrives at `basecampconsultants@gmail.com`.

## 5) Optional custom domain
- In Render service settings, open `Custom Domains`.
- Add your domain and follow DNS instructions.
