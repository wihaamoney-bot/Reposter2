# Security Policy

## Reporting Security Issues

If you discover a security vulnerability, please email security@yoursite.com instead of using the issue tracker. We will investigate and address the issue as soon as possible.

## Security Measures Implemented

### Authentication & Authorization
- All passwords are hashed with bcrypt (via werkzeug.security)
- Constant-time password comparison to prevent timing attacks
- Session-based authentication with Flask-Login
- Secure session cookies (HTTPOnly, Secure, SameSite=Strict)
- Session timeout: 24 hours
- Session fixation protection (new session on login)
- Device-based Telegram authorization isolation

### API Security
- All endpoints require authentication (`@login_required`)
- CSRF protection enabled via Flask-WTF
- Rate limiting on critical endpoints:
  - Send code: 10/5min per device, 3/5min per phone, 5/5min per IP
  - Resend code: 3/5min per phone
  - Verify code: 10/5min per device, 5/5min per phone
  - Unique phone limit: 3 different numbers per 24 hours per device
- Exponential backoff on repeated failed attempts
- Idempotent request handling to prevent duplicate submissions

### Data Protection
- Phone code hashes encrypted using Fernet symmetric encryption
- Database credentials stored in environment variables
- No sensitive data logged in production
- SQL injection protection via SQLAlchemy ORM (parameterized queries)
- Input validation and sanitization

### File Upload Security
- File extension whitelist (png, jpg, jpeg, gif, webp)
- File size limit: 10MB per file
- Path traversal protection (no "..", no absolute paths)
- MIME type validation via Pillow
- Image integrity verification
- Secure filename generation with UUID and timestamp

### XSS Protection
- Auto-escaping in Jinja2 templates
- Manual HTML escaping in JavaScript for user content
- Content-Security-Policy headers

### Session Management
- Clear session on logout
- Device ID tracking for multi-device support
- Telegram authorization state synced between session and database
- Automatic cleanup of expired sessions

## Known Security Considerations

### Rate Limiting
Custom rate limiting implementation using database-backed tracking. Ensure database has adequate capacity for request logging.

### Telegram Session Files
Session files are stored in `sessions/` directory and contain authentication tokens. These files:
- Are excluded from version control (.gitignore)
- Should have restricted file permissions (600 or 640)
- Are deleted when user explicitly removes session

### Encryption Key
The application requires `ENCRYPTION_KEY` environment variable for Fernet encryption:
- Generate with: `python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"`
- Store securely in .env file
- Rotate periodically
- Backup securely

### Database Connection
- PostgreSQL recommended for production (prevents SQLite locking issues)
- Connection pooling configured (pool_size=20, max_overflow=40)
- Connection recycling every 5 minutes
- Statement timeout: 30 seconds

## Recommended Deployment Security

### Production Checklist
- [ ] Set `FLASK_ENV=production` and `FLASK_DEBUG=False`
- [ ] Use HTTPS with valid SSL/TLS certificate
- [ ] Configure firewall (only ports 80, 443 accessible)
- [ ] Restrict SSH access (key-based auth, non-standard port, IP whitelist)
- [ ] Database accessible only from application server
- [ ] Regular security updates for OS and dependencies
- [ ] Implement log monitoring and alerting
- [ ] Regular database backups (encrypted, off-site storage)
- [ ] Use secrets management for environment variables
- [ ] Enable WAF if using cloud hosting

### Headers
The following security headers are configured:
- `X-Frame-Options: DENY` - Prevents clickjacking
- `X-Content-Type-Options: nosniff` - Prevents MIME sniffing
- `X-XSS-Protection: 1; mode=block` - XSS protection
- `Strict-Transport-Security: max-age=31536000; includeSubDomains` - HSTS
- `Referrer-Policy: strict-origin-when-cross-origin`
- `Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline' cdn.jsdelivr.net; style-src 'self' 'unsafe-inline' cdn.jsdelivr.net`
- `Cache-Control: no-store, no-cache, must-revalidate` for sensitive endpoints

## Dependencies

Security-related dependencies:
- `cryptography>=41.0.0` - For encryption of sensitive data
- `werkzeug` - For password hashing and security utilities
- `Flask-WTF` - For CSRF protection

Regular updates should be performed for all dependencies. Use:
```bash
pip install --upgrade pip
pip install --upgrade -r requirements.txt
pip check  # Check for conflicts
```

## Logging

Security event logging includes:
- Login attempts (success/failure)
- Telegram authorization attempts
- Code send/verify attempts
- Session management events
- Failed authentication attempts

**Important**: Sensitive data (passwords, codes, tokens) is NOT logged.

## Incident Response

In case of suspected compromise:
1. Immediately revoke all Telegram sessions via `/api/telegram/logout`
2. Rotate the SECRET_KEY and ENCRYPTION_KEY
3. Change all admin passwords
4. Review logs for unauthorized access
5. Audit scheduled tasks and message logs
6. Notify users if their data may be affected
7. Document the incident and improve security measures

## Version History

### v1.0.0
- Initial security implementation
- CSRF protection
- Rate limiting
- Encrypted sensitive data
- Secure file uploads
- SQL injection protection via ORM
