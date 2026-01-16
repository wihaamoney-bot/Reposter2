# Test Plan for Telegram Setup Session Sync Fix

## Test Scenarios

### Scenario 1: Fresh Telegram Authorization
**Steps:**
1. Login to the application with admin credentials
2. Enter phone number on Telegram auth page
3. Receive and enter verification code
4. Verify success message shows "Setup completed"
5. Verify automatic redirect to contacts page

**Expected Results:**
- Success message displays "Setup completed"
- Automatic redirect to `/contacts` after 1.5 seconds
- Logs show: `Установлен флаг telegram_authorized=True в сессии для user_id=X`

### Scenario 2: Page Reload After Authorization
**Steps:**
1. Complete Scenario 1 successfully
2. Reload the page (F5 or Ctrl+R)
3. Navigate to root URL `/`

**Expected Results:**
- User is automatically redirected to `/contacts` (not `/telegram_auth`)
- No "setup required" message appears
- Logs show: `Синхронизация сессии с БД` (if session was lost)
- Logs show: `User X авторизован в Telegram, перенаправление на contacts`

### Scenario 3: Re-login After Authorization
**Steps:**
1. Complete Scenario 1 successfully
2. Logout
3. Login again with same credentials

**Expected Results:**
- User is automatically redirected to `/contacts` (not `/telegram_auth`)
- Logs show: `Инициализирована сессия с telegram_authorized=True из БД`
- No need to re-authorize with Telegram

### Scenario 4: 2FA Password Flow
**Steps:**
1. Login to the application
2. Enter phone number for account with 2FA enabled
3. Enter verification code
4. System should request 2FA password
5. Enter 2FA password
6. Verify success message shows "Setup completed"

**Expected Results:**
- Password step appears after code verification
- Success message displays "Setup completed" (or custom message from API)
- Automatic redirect to `/contacts`
- Session flag is properly set and persists

### Scenario 5: Session Synchronization
**Steps:**
1. Complete authorization
2. Manually clear Flask session cookie (via browser dev tools)
3. Reload the page

**Expected Results:**
- Session is restored from database
- User sees contacts page (not setup page)
- Logs show: `Синхронизация сессии с БД для user_id=X: установка telegram_authorized=True`

## Log Verification Checklist

Check that the following log entries appear in the appropriate scenarios:

- [ ] `Установлен флаг telegram_authorized=True в сессии для user_id=X` (after successful auth)
- [ ] `Синхронизация сессии с БД для user_id=X: установка telegram_authorized=True` (on session sync)
- [ ] `Инициализирована сессия с telegram_authorized=True из БД` (on login with existing auth)
- [ ] `User X авторизован в Telegram, перенаправление на contacts` (on index redirect)
- [ ] `User X не авторизован в Telegram, перенаправление на telegram_auth` (on index redirect when not auth)

## Edge Cases to Test

1. **Multiple browser sessions**: Open in two different browsers, authorize in one, check if the other syncs on reload
2. **Session expiry**: Wait for session timeout, then reload - should sync from DB
3. **Concurrent authorization attempts**: Try to authorize from two devices/browsers simultaneously
4. **Network interruption**: Start authorization, disconnect network, reconnect, verify completion

## Success Criteria

✅ All test scenarios pass
✅ All expected log entries appear
✅ No "setup required" loop after successful authorization
✅ Page reloads correctly redirect to contacts
✅ Session state matches database state at all times
