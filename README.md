# PayTrix Bot - Bank Automation System

**Internal Documentation for The PayTrix Operations Team**

## Overview

PayTrix Bot is our automated financial data aggregation system that monitors multiple bank accounts, downloads statements, and provides real-time balance alerts across Indian banking institutions.

### Supported Banks

- **TMB** (Tamilnad Mercantile Bank)
- **IOB** (Indian Overseas Bank - Retail & Corporate)
- **KGB** (Kerala Gramin Bank)
- **IDBI** (IDBI Bank)
- **IDFC** (IDFC First Bank)
- **Canara** (Canara Bank)

### Core Features

- Automated daily statement downloads
- Real-time balance monitoring with Telegram alerts
- Multi-account concurrent processing
- Automatic CAPTCHA solving
- Error recovery and retry mechanisms

---

## Quick Start

### Prerequisites

1. **Python 3.8+** installed
2. **Google Chrome** browser
3. **Telegram Bot Token** (contact IT if you don't have one)
4. **Access to credentials CSV** (ask your manager)

### Installation

```bash
# Clone the repository
git clone <repository-url>
cd paytrix-bot

# Create virtual environment
python -m venv .venv

# Activate virtual environment
# Windows:
.venv\Scripts\activate
# Linux/Mac:
source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

### Configuration

1. **Copy the example environment file:**
```bash
cp .env.example .env
```

2. **Edit `.env` file with your credentials:**
```env
TELEGRAM_TOKEN=<your-bot-token>
TELEGRAM_CHAT_ID=<your-chat-id>
CREDENTIALS_CSV=tmb_credentials.csv
TWO_CAPTCHA_API_KEY=<captcha-api-key>
ALERT_GROUP_IDS=<alert-group-ids>
```

3. **Verify credentials CSV exists:**
   - File should be named as specified in `CREDENTIALS_CSV`
   - Contact your manager if you need the credentials file

### Running the Bot

**Windows:**
```bash
start_bot.bat
```

**Linux/Mac:**
```bash
source .venv/bin/activate
python -m payatom_bot.app
```

---

## Daily Operations

### Starting Account Monitoring

```
/run <alias>                    # Start single account
/run alias1 alias2 alias3       # Start multiple accounts
```

**Example:**
```
/run madras_tmb jivisan_tmb
```

### Checking Status

```
/running                        # List all active workers
/active                         # Check upload status
/balance                        # View all balances
/balance alias1 alias2          # View specific balances
```

### Managing Workers

```
/stop <alias>                   # Stop specific worker
/stopall                        # Stop all workers
/status <alias>                 # Get screenshots of worker status
```

### Retrieving Files

```
/file <alias>                   # Download latest statement
```

---

## Account Management

### Adding New Account

```
# For TMB, IOB, KGB, IDBI, IDFC (4 fields):
/add alias,username,password,account_number

# For IOB Corporate (5 fields):
/add alias,login_id,user_id,password,account_number
```

**Example:**
```
/add newaccount_tmb,USER123,Pass@123,1234567890
```

### Editing Account Credentials

```
/edit <alias>
```

Then select what to change from the menu and provide new value.

### Viewing All Accounts

```
/list                           # Show all configured accounts
```

---

## Balance Alerts

### Alert Thresholds

The system automatically sends alerts at these levels:

| Amount | Priority | Action |
|--------|----------|--------|
| ₹50,000 | Low | Monitor activity |
| ₹60,000 | Low-Medium | Watch closely |
| ₹70,000 | Medium | Transfer funds urgently |
| ₹90,000 | High | Immediate action required |
| ₹100,000+ | **CRITICAL** | Stop operations & transfer now |

### Alert Commands

```
/alerts                         # View monitoring status
/balances                       # Detailed balance check
/reset_alerts <alias>           # Reset alerts after fund transfer
/reset_alerts all               # Reset all alerts
```

**Note:** Alerts repeat every 5 minutes until balance drops below threshold.

---

## Troubleshooting

### Bot Not Responding

1. Check if bot process is running
2. Restart the bot:
   ```bash
   # Stop current process (Ctrl+C)
   # Restart
   start_bot.bat  # Windows
   # OR
   python -m payatom_bot.app  # Linux/Mac
   ```

### Worker Login Failed

**Symptoms:** Worker stops after "Logged out" or "CAPTCHA incorrect"

**Solutions:**
1. Check credentials in CSV file are correct
2. Verify 2Captcha API has balance (check: https://2captcha.com)
3. Use `/stop <alias>` then `/run <alias>` to restart
4. Check error screenshots in Telegram for details

### Statement Download Failed

**Symptoms:** "Timed out waiting for download"

**Solutions:**
1. Check disk space: `df -h` (Linux) or check drive properties (Windows)
2. Verify downloads folder exists and is writable
3. Restart worker: `/stop <alias>` then `/run <alias>`

### Balance Not Updating

**Symptoms:** Shows "loading..." or old balance

**Solutions:**
1. Worker may be stuck - check `/active`
2. Restart worker: `/stop <alias>` then `/run <alias>`
3. Bank website may be down - verify manually

### CAPTCHA Solving Issues

**Symptoms:** Repeated "CAPTCHA incorrect" errors

**Solutions:**
1. Check 2Captcha balance at https://2captcha.com
2. Manually solve CAPTCHA when bot sends image to Telegram
3. Contact IT if issues persist

---

## File Locations

```
paytrix-bot/
├── downloads/              # Downloaded statements (organized by alias)
│   ├── madras_tmb/
│   ├── jivisan_tmb/
│   └── ...
├── chrome-profiles/        # Browser profiles (auto-managed)
├── .env                    # Configuration (DO NOT COMMIT)
├── tmb_credentials.csv     # Account credentials (DO NOT COMMIT)
└── payatom_bot/           # Application code
```

---

## Security Guidelines

### Critical Security Rules

1. **NEVER commit `.env` or credentials CSV to Git**
2. **DO NOT share Telegram bot token publicly**
3. **Restrict access to credentials file** (file permissions: read-only for your user)
4. **Use company VPN** when running the bot remotely
5. **Log out of Telegram Web** after viewing sensitive messages

### Getting Telegram IDs

**For personal chat ID:**
1. Message @RawDataBot on Telegram
2. Copy the `"chat": {"id": <number>}` value
3. Use this as `TELEGRAM_CHAT_ID`

**For group alert IDs:**
1. Add @RawDataBot to the group
2. Copy the chat ID (negative number like `-1001234567890`)
3. Remove the bot
4. Add to `ALERT_GROUP_IDS` (comma-separated for multiple groups)

---

## Best Practices

### Starting Your Day

1. Run `/running` to check active workers
2. Run `/active` to verify recent uploads
3. Check `/alerts` for any threshold violations
4. Start any stopped workers with `/run <alias>`

### Before Leaving

1. Verify all critical accounts are running: `/running`
2. Check for any error messages in Telegram
3. Ensure balance alerts are configured: `/alerts`

### Weekly Maintenance

1. Review downloaded files in `downloads/` folder
2. Clear old files (>7 days) if needed
3. Verify 2Captcha balance is sufficient
4. Check for any workers that frequently crash

### When Transferring Funds

After transferring money from an account:
```
/reset_alerts <alias>
```
This ensures you'll receive new alerts when thresholds are crossed again.

---

## Support

### Internal Support

- **Technical Issues:** Contact IT Team
- **Credential Access:** Contact your Manager
- **Bot Token Issues:** Contact DevOps Team
- **Balance Alert Questions:** Contact Finance Team

### Useful Commands Reference

```
# Session Management
/run <alias>                    Start worker
/stop <alias>                   Stop worker
/stopall                        Stop all workers
/running                        List active workers

# Monitoring
/balance [alias...]             Show balances
/active                         Check upload status
/status <alias>                 Get screenshots
/file <alias>                   Download statement

# Configuration
/list                           Show all accounts
/add <details>                  Add account
/edit <alias>                   Edit account

# Alerts
/alerts                         Alert system status
/balances                       Detailed balance check
/reset_alerts <alias>           Reset alerts
```

---

## Deployment Notes

### Production Server

If deploying on a dedicated server:

1. **Use screen or tmux to keep bot running:**
```bash
screen -S paytrix-bot
source .venv/bin/activate
python -m payatom_bot.app
# Press Ctrl+A, then D to detach
```

2. **Reattach to check status:**
```bash
screen -r paytrix-bot
```

3. **Set up auto-start (optional):**
Create systemd service file at `/etc/systemd/system/paytrix-bot.service`

### Environment Variables for Production

```env
# Production settings
BALANCE_CHECK_INTERVAL=180      # Check every 3 minutes
ALERT_GROUP_IDS=-100xxx,-100yyy # Multiple alert groups
```

---

## Changelog

Keep track of major changes:

- **v2.0** - Added balance monitoring system
- **v1.5** - Added Canara Bank support
- **v1.4** - Enhanced error handling with ErrorContext
- **v1.3** - Added /file command for statement retrieval
- **v1.0** - Initial release with TMB, IOB, KGB support

---

**Last Updated:** December 2024  
**Maintained By:** The PayTrix Development Team