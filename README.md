# Reposter2 - Telegram Sender

## Security Setup

1. Generate encryption key:
   ```bash
   python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
   ```
   
2. Set `ENCRYPTION_KEY` in `.env`

3. Never commit sensitive files:
   - `config.json`
   - `.env`
   - `sessions/*.session`
   - `logs/`

## Cleanup

To clean up old data (logs, sessions > 7 days, uploads > 24 hours), run:
```bash
./cleanup_data.sh
```
