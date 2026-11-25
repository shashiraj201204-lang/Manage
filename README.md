# XIRUS Telegram Manager

## Included
- Single Flask backend (`app.py`) and separate UI (`xirus.html`)
- Telegram OTP login and optional Telegram 2-step verification
- Multiple saved accounts
- Encrypted Telegram StringSession values in SQLite
- 30-day remembered website login per browser/device
- Separate password gate for read-only chat viewing
- Chat list, recent text messages, basic statistics
- Remove one saved account / log off all saved accounts
- JSON export of account metadata (never exports session secrets)

## Important security limits
- A browser/device must authenticate separately. It is not safe to make every unknown device automatically logged in because another device logged in once.
- `WEB_PASSWORD` and `CHAT_PASSWORD` are separate. Do not use a weak shared password. If you specifically choose `shashi123`, anyone who learns it can unlock the chat reader.
- Telegram sessions are powerful credentials. Keep the Render service private, use a strong unique password, enable Telegram 2-step verification, and never share OTP/API hash/session data.
- The chat reader is read-only. It does not delete messages or bypass private group/channel membership.
- The Render persistent disk is required to keep the encrypted account database across deploys/restarts. Do not remove it.
- Pending OTP login attempts are held in memory and must be restarted if the service restarts mid-login.
- This project is a personal-use starting implementation, not a security-audited product.

## Render setup
1. Create a new Web Service from this folder/repository.
2. Use `render.yaml`, or set:
   - Build: `pip install -r requirements.txt`
   - Start: `gunicorn app:app --workers 1 --threads 4 --timeout 120`
3. Attach a persistent disk mounted at `/var/data` (1 GB is enough for initial personal use).
4. Add environment variables:
   - `DATA_DIR=/var/data`
   - `TG_API_ID` = your Telegram API ID
   - `TG_API_HASH` = your Telegram API hash
   - `WEB_PASSWORD` = strong unique website password
   - `CHAT_PASSWORD` = strong separate chat-section password
   - `FLASK_SECRET_KEY` = random long secret
   - `FERNET_KEY` = Fernet key
5. Generate a Fernet key locally:
   `python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"`
6. Set `FLASK_SECRET_KEY` to a different random value, for example generated with:
   `python -c "import secrets; print(secrets.token_urlsafe(48))"`
7. Deploy. Open the Render URL, sign in, then add your Telegram account.

## Notes
- Login codes are entered only on your own private dashboard. Never send them to anyone.
- The UI remembers a successful website login on that same browser for up to 30 days. New devices must sign in separately.
- The website logout removes its browser cookie. "Log off all accounts" deletes saved Telegram sessions from this website; it does not revoke sessions in Telegram itself. To revoke Telegram sessions, use Telegram Settings > Devices.
