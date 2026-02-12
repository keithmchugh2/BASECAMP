# BASECAMP Member App (V1)

This is the app version of BASECAMP with:
- Member authentication
- Paid-member gated areas
- Tools & docs library
- Custom workout delivery
- Mastermind opt-in + group posts
- Events/retreats feed
- Admin console for managing everything

## Run locally

1. Create venv and install dependencies:

```bash
cd "/Users/kmchugh/Library/CloudStorage/OneDrive-Omnissa/Keith/Personal/BASECAMP"
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements-member-app.txt
```

2. Optional env vars:

```bash
export BASECAMP_APP_SECRET="replace-with-random-secret"
export BASECAMP_ADMIN_EMAIL="basecampconsultants@gmail.com"
export BASECAMP_ADMIN_PASSWORD="ChangeThisNow123!"
```

3. Run app:

```bash
python3 member_app/app.py
```

Open: `http://localhost:5000`

## First login

Default admin is created automatically from env vars.
If none provided:
- Email: `admin@basecamp.local`
- Password: `ChangeThisNow123!`

Change this immediately in production.

## Stripe integration notes

The app includes a ready endpoint at `/webhooks/stripe`.
To complete billing automation:
1. Create Stripe checkout + customer mapping.
2. On successful webhook event, set `users.is_paid = 1`.
3. Set env vars for Stripe keys.

## Production deployment

Deploy as a separate Render service (recommended) so it does not replace your marketing site service.
Start command:

```bash
python member_app/app.py
```
