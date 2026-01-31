# 📧 Email Verifier System

A powerful Django-based email verification system with **Celery** and **Redis** for asynchronous bulk email verification. Capable of processing 10,000+ emails with real-time progress tracking.

![Python](https://img.shields.io/badge/Python-3.10+-blue)
![Django](https://img.shields.io/badge/Django-6.0.1-green)
![Celery](https://img.shields.io/badge/Celery-5.3.4-brightgreen)
![Redis](https://img.shields.io/badge/Redis-5.0.1-red)

## ✨ Features

- ✅ **6-Layer Verification Pipeline**
  - Syntax Validation (Regex)
  - Domain Lookup (NS records)
  - MX Records Check
  - SMTP Handshake
  - Disposable Email Detection
  - Catch-all Detection

- ✅ **Asynchronous Processing**
  - Celery task queue
  - Redis message broker
  - Batch processing
  - Progress tracking

- ✅ **Flexible Input**
  - CSV file upload
  - TXT file upload
  - JSON API
  - Single email verification

- ✅ **Comprehensive API**
  - RESTful endpoints
  - Paginated results
  - CSV export
  - Real-time status updates

- ✅ **Production Ready**
  - Rate limiting
  - Error handling & retries
  - Database indexing
  - Admin dashboard

## 🚀 Quick Start

### 1. Install Redis

**Windows:**
```powershell
choco install redis-64
redis-server
```

**Linux/Mac:**
```bash
sudo apt-get install redis-server  # Ubuntu
brew install redis                  # Mac
```

### 2. Install Dependencies

```powershell
pip install -r requirements.txt
```

### 3. Run Migrations

```powershell
python manage.py makemigrations
python manage.py migrate
python manage.py createsuperuser
```

### 4. Start Services (3 terminals)

**Terminal 1 - Django:**
```powershell
python manage.py runserver
```

**Terminal 2 - Celery:**
```powershell
celery -A core worker --loglevel=info --pool=solo
```

**Terminal 3 - Redis:**
```powershell
redis-server
```

### 5. Test the System

```powershell
python test_system.py
```

## 📚 Documentation

- **[CELERY_SETUP.md](CELERY_SETUP.md)** - Complete setup and usage guide
- **[IMPLEMENTATION_SUMMARY.md](IMPLEMENTATION_SUMMARY.md)** - Feature overview
- **[DIRECTORY_STRUCTURE.md](DIRECTORY_STRUCTURE.md)** - Project structure

## 🔌 API Endpoints

### Create Bulk Verification Job
```bash
POST /api/verify/bulk/
Content-Type: application/json

{
  "emails": ["user1@example.com", "user2@example.com"]
}
```

### Check Job Status
```bash
GET /api/jobs/{job_id}/status/
```

**Response:**
```json
{
  "job_id": "abc-123",
  "status": "processing",
  "progress_percentage": 45.0,
  "total_count": 1000,
  "processed_count": 450,
  "valid_count": 320,
  "invalid_count": 130
}
```

### Get Results
```bash
GET /api/jobs/{job_id}/results/?page=1&page_size=50
```

### Download CSV
```bash
GET /api/jobs/{job_id}/download/
```

### Verify Single Email
```bash
POST /api/verify/single/
Content-Type: application/json

{
  "email": "test@example.com"
}
```

## 🗄️ Database Schema

### VerificationJob
- `job_id` (UUID) - Primary key
- `total_count` - Total emails to verify
- `processed_count` - Emails processed
- `valid_count` - Valid emails found
- `invalid_count` - Invalid emails found
- `status` - pending/processing/completed/failed
- `progress_percentage` - Completion percentage

### EmailResult
- `email` - Email address
- `status` - valid/invalid/risky/unknown
- `syntax_valid` - Passed syntax check
- `domain_exists` - Domain has NS records
- `mx_records_found` - Has MX records
- `smtp_valid` - Passed SMTP check
- `is_disposable` - Is disposable email
- `is_catch_all` - Domain is catch-all
- `reason` - Verification result reason
- `mx_records` - List of MX servers
- `verification_time_ms` - Time taken

## ⚙️ Configuration

Edit `core/settings.py`:

```python
# SMTP Verification
SMTP_TIMEOUT = 10
SMTP_CHECK_ENABLED = True  # Set False for faster verification

# DNS Settings
DNS_TIMEOUT = 2.0
DNS_NAMESERVERS = ['8.8.8.8', '1.1.1.1']

# Processing
VERIFICATION_BATCH_SIZE = 50  # Emails per batch
MAX_CONCURRENT_VERIFICATIONS = 100
```

## 📊 Performance

- **Speed**: ~1-2 seconds per email (with SMTP)
- **Speed**: ~0.5 seconds per email (without SMTP)
- **Throughput**: 100+ emails/minute
- **Scalability**: Add more Celery workers for parallel processing

### For 10,000+ Emails:

1. Disable SMTP checks: `SMTP_CHECK_ENABLED = False`
2. Increase batch size: `VERIFICATION_BATCH_SIZE = 100`
3. Add more workers: `celery -A core worker --concurrency=4`
4. Use PostgreSQL instead of SQLite

## 🧪 Testing

### Run Test Suite
```powershell
python test_system.py
```

### Test with Sample Data
```powershell
curl -X POST http://localhost:8000/api/verify/bulk/ -F "file=@sample_emails.csv"
```

## 🔧 Troubleshooting

### Celery won't start on Windows
```powershell
celery -A core worker --loglevel=info --pool=solo
```

### Redis connection error
```powershell
redis-cli ping  # Should return PONG
```

### Tasks not executing
1. Check Redis is running
2. Check Celery worker is running
3. Check worker logs for errors

## 📈 Monitoring

### Celery Status
```powershell
celery -A core inspect active
celery -A core inspect stats
```

### Install Flower (Celery monitoring)
```powershell
pip install flower
celery -A core flower
# Visit http://localhost:5555
```

## 🔐 Security

- ✅ Rate limiting (10 emails/minute for SMTP)
- ✅ DNS/SMTP timeouts
- ✅ Input validation
- ✅ Error handling
- ✅ User authentication support

## 🌐 Production Deployment

1. **Use PostgreSQL** instead of SQLite
2. **Set DEBUG = False** in settings.py
3. **Use environment variables** for secrets
4. **Set up Supervisor/Systemd** for Celery workers
5. **Configure Redis persistence**
6. **Use Nginx/Apache** as reverse proxy
7. **Enable HTTPS**

## 📁 Project Structure

```
Email_Verifier/
├── core/                    # Django project
│   ├── celery.py           # Celery config
│   └── settings.py         # Django + Celery settings
├── verifier/               # Main app
│   ├── models.py           # Database models
│   ├── tasks.py            # Celery tasks
│   ├── views.py            # API views
│   └── urls.py             # URL routing
├── requirements.txt        # Dependencies
├── CELERY_SETUP.md        # Setup guide
└── test_system.py         # Test suite
```

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Run tests
5. Submit a pull request

## 📝 License

This project is licensed under the MIT License.

## 🆘 Support

- **Documentation**: See `CELERY_SETUP.md`
- **Issues**: Check Celery/Django logs
- **Admin Panel**: http://localhost:8000/django-admin/

## 🎯 Roadmap

- [ ] WebSocket support for real-time updates
- [ ] Email reputation scoring
- [ ] DMARC/SPF/DKIM validation
- [ ] API rate limiting
- [ ] User dashboard improvements
- [ ] Export to multiple formats (JSON, Excel)
- [ ] Scheduled verification jobs
- [ ] Email list management

## 📞 Contact

For questions or support, please check the documentation or create an issue.

---

**Built with ❤️ using Django, Celery, and Redis**

**Version:** 1.0  
**Last Updated:** 2026-01-25
