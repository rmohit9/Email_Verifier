```markdown
# Email Campaign — Combined Documentation

This document consolidates the setup, architecture, and quick-start guides for the Email Campaign feature.

---

## Overview
This feature allows admins to:
- Upload CSV files with email lists
- Create email campaigns with subject and HTML message
- Send bulk emails via Brevo Transactional Email API v3
- Track sending progress and logs
- Handle rate limiting and error management

---

## Quick Start (5-Minute)

1. Get Brevo API Key
```bash
# Go to https://www.brevo.com → Settings → SMTP & API
# Copy your API v3 key
```

2. Configure environment (create `.env` in project root):
```bash
BREVO_API_KEY=your_api_key_here
BREVO_SENDER_NAME=Your Company
BREVO_SENDER_EMAIL=noreply@yourdomain.com
```

3. Run migrations:
```bash
python manage.py makemigrations
python manage.py migrate
```

4. Open the UI: `http://localhost:8000/email-campaign/`

---

## Models

### `EmailCampaign`
- `campaign_id` (UUID, PK)
- `user` (FK → User)
- `subject`, `message`, `csv_filename`
- `total_recipients`, `sent_count`, `failed_count`, `skipped_count`
- `status` (draft, scheduled, sending, completed, failed)
- `progress_percentage`, timestamps, `error_message`
- Optional fields: `batch_size`, `delay_between_batches`, `sender_name`, `sender_email`, `reply_to`, `schedule_at`, `tags`, `enable_open_tracking`, `enable_click_tracking`

### `CampaignRecipient`
- One record per recipient: `email`, `status` (pending/sent/failed/skipped), `sent_at`, `brevo_message_id`, `error_message`, `created_at`
- Unique constraint `(campaign, email)`

### `CampaignLog`
- Activity log for each campaign: `level` (info/warning/error/success), `message`, optional `recipient`, `created_at`

---

## Architecture & Flow

1. Frontend (`email_campaign.html`) — CSV upload, subject, HTML editor, advanced options, send button.
2. API (`EmailCampaignViewSet`) — `create()`, `send()`, `recipients()`, `logs()`, `cancel()`.
3. Brevo client (`BrevoAPIClient`) — `send_email()` and batch helpers.
4. Database — `EmailCampaign`, `CampaignRecipient`, `CampaignLog`.
5. Response — JSON with status, counts, and failed recipients.

Key implementation patterns: CSV validation, batch sending with rate limits, three-layer error tracking (campaign/recipient/log), optional Celery tasks for async.

---

## API Endpoints

- `POST /api/campaigns/` — Create campaign (multipart form: `subject`, `message`, `csv_file`)
- `GET /api/campaigns/` — List campaigns (admin sees all)
- `GET /api/campaigns/{id}/` — Retrieve campaign
- `POST /api/campaigns/{id}/send/` — Send campaign (synchronous by default)
- `GET /api/campaigns/{id}/recipients/` — List recipients (filter `?status=`)
- `GET /api/campaigns/{id}/logs/` — Campaign logs
- `POST /api/campaigns/{id}/cancel/` — Cancel campaign (deletes pending recipients)

Example: Create campaign (curl)
```bash
curl -X POST http://localhost:8000/api/campaigns/ \
  -F "subject=Welcome" \
  -F "message=<h1>Hello</h1>" \
  -F "csv_file=@emails.csv"
```

---

## Frontend

Access at `/email-campaign/`:
- CSV drag-and-drop or paste
- Subject input
- Rich HTML editor (basic toolbar)
- Advanced settings: sender, batch size, delay, schedule, tags, toggles
- Recent campaigns table with actions

CSV format:
```
email
user1@example.com
user2@example.com
```
- Must include `email` header (case-insensitive)
- Max file size 5MB
- Duplicates removed

---

## Sending Process

1. Parse/validate CSV, dedupe
2. Create `EmailCampaign` with recipients in `CampaignRecipient` (status `pending`)
3. `send()` initializes `BrevoAPIClient` and sends recipients in batches
4. Update `CampaignRecipient` status and `EmailCampaign` progress
5. Log events to `CampaignLog`

Defaults: `batch_size=50`, `delay_between_batches=1.0s` (configurable per campaign)

Synchronous good for small lists (<1000). For large lists use Celery async (`send_campaign_emails.delay(campaign_id)`).

---

## Error Handling & Logging

- Campaign-level errors in `EmailCampaign.error_message` (fatal)
- Recipient-level errors in `CampaignRecipient.error_message`
- Activity in `CampaignLog` with `level` and optional `recipient`

---

## Migrations

Apply migrations after adding models:
```bash
python manage.py makemigrations
python manage.py migrate
```

---

## Configuration (core/settings.py)

Add environment variables (via `.env`):
```python
BREVO_API_KEY = os.getenv('BREVO_API_KEY', '')
BREVO_SENDER_NAME = os.getenv('BREVO_SENDER_NAME', 'Email Campaign')
BREVO_SENDER_EMAIL = os.getenv('BREVO_SENDER_EMAIL', 'noreply@example.com')
# Optional Celery
CELERY_BROKER_URL = os.getenv('CELERY_BROKER_URL', 'redis://localhost:6379/0')
```

---

## Troubleshooting

- `BREVO_API_KEY` not set → verify `.env` and load_dotenv
- Campaign stuck in `sending` → inspect `CampaignLog` and app logs
- Recipients not receiving → ensure sender email is Brevo-verified and check recipient errors

---

## Performance & Scaling

For large campaigns (>10k): use Celery with multiple workers, shard recipients, monitor queue depth, add DB indexes on `CampaignRecipient(campaign, status)` and `CampaignRecipient.email`.

---

## Security & Best Practices

- Store API keys in env variables, do not commit `.env`
- Validate/sanitize CSV and inputs
- Use HTTPS in production
- Apply proper access control: only authenticated users, restrict creation to admins if desired

---

## Admin

Access at `/admin/verifier/emailcampaign/`, `/admin/verifier/campaignrecipient/`, `/admin/verifier/campaignlog/`

---

## Next Steps & Recommendations

1. Test with a small sample campaign (10 emails)
2. Configure and verify Brevo sender email
3. If sending >1000 emails, enable Celery and use background tasks
4. Add monitoring/alerts for failures and API quotas

---

## References
- Brevo Docs: https://developers.brevo.com/docs
- Django REST Framework

``` 