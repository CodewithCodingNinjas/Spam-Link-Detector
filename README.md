# 🛡 AI Real-Time Scam Link Detector

> AI-powered Real-Time URL Threat Intelligence System for detecting phishing and scam links circulating on messaging platforms.

## 📋 Overview

This project is a complete **Android app + FastAPI backend** system that analyzes URLs for phishing, scam, and malware threats. Users can scan suspicious links from WhatsApp, Telegram, SMS, or any other source and get an instant threat assessment.

### Architecture

```
Android App (Kotlin)
      ↓ HTTPS
AWS EC2 / Docker
      ↓
FastAPI Server
      ↓
ML Model + Threat Intelligence Engine
```

---

## 🚀 Features

### Android App
- **Manual URL Scanner** — Paste or type any URL and tap "Scan Now"
- **Share-to-Scan** — Share links directly from WhatsApp/Telegram to the app
- **Clipboard Monitoring** — Detects copied URLs and offers to scan them
- **Scan History** — Complete local history with Room database
- **Detailed Threat Reports** — Domain age, SSL, keywords, ML prediction, brand impersonation
- **QR Code Scanner** — Scan QR codes and auto-check extracted URLs

### Backend API
- **ML Phishing Detection** — Random Forest / Gradient Boosting trained model
- **URL Feature Extraction** — 27+ structural features analyzed
- **Domain Intelligence** — WHOIS-based domain age checking
- **SSL Validation** — Certificate validity, issuer, and expiry checking
- **Brand Impersonation Detection** — Fuzzy matching against 40+ known brands
- **Google Safe Browsing API** — Cross-referencing with Google's threat database
- **Weighted Risk Scoring** — Combined 0-100 risk score with confidence level

---

## 🛠 Tech Stack

### Backend
| Technology | Purpose |
|---|---|
| Python 3.10+ | Runtime |
| FastAPI | Web framework |
| Uvicorn | ASGI server |
| Scikit-learn | ML model training |
| Pandas / NumPy | Data processing |
| python-whois | Domain WHOIS lookups |
| RapidFuzz | Fuzzy string matching |
| SQLAlchemy | Database ORM |
| Docker | Containerization |

### Android
| Technology | Purpose |
|---|---|
| Kotlin | Primary language |
| Retrofit | HTTP client |
| Room | Local database |
| ViewModel + LiveData | Architecture |
| Material Design 3 | UI components |
| CameraX + ML Kit | QR code scanning |
| Coroutines | Async operations |

---

## 📁 Project Structure

```
Spam Detection/
├── backend/
│   ├── main.py                 # FastAPI application entry
│   ├── config.py               # Configuration & settings
│   ├── database.py             # SQLAlchemy models & DB setup
│   ├── schemas.py              # Pydantic request/response models
│   ├── requirements.txt        # Python dependencies
│   ├── Dockerfile              # Container build
│   ├── .env.example            # Environment variables template
│   ├── modules/
│   │   ├── url_features.py     # URL feature extraction (27+ features)
│   │   ├── domain_intel.py     # WHOIS domain age analysis
│   │   ├── ssl_checker.py      # SSL certificate validation
│   │   ├── brand_impersonation.py  # Fuzzy brand matching
│   │   ├── safe_browsing.py    # Google Safe Browsing API
│   │   └── risk_engine.py      # Final weighted risk scoring
│   └── ml/
│       ├── train_model.py      # ML model training script
│       └── predictor.py        # Model inference module
│
├── android/
│   ├── app/
│   │   ├── build.gradle.kts    # App dependencies
│   │   └── src/main/
│   │       ├── AndroidManifest.xml
│   │       ├── java/com/scamdetector/app/
│   │       │   ├── ScamDetectorApp.kt
│   │       │   ├── data/
│   │       │   │   ├── model/Models.kt
│   │       │   │   ├── local/           # Room DB
│   │       │   │   ├── remote/          # Retrofit API
│   │       │   │   └── repository/      # Data repository
│   │       │   ├── ui/
│   │       │   │   ├── MainActivity.kt
│   │       │   │   ├── ScanDetailActivity.kt
│   │       │   │   ├── QRScannerActivity.kt
│   │       │   │   ├── MainViewModel.kt
│   │       │   │   └── adapter/
│   │       │   └── service/
│   │       │       └── ClipboardMonitorService.kt
│   │       └── res/                     # Layouts, drawables, values
│   ├── build.gradle.kts
│   └── settings.gradle.kts
│
├── docker-compose.yml
├── nginx/nginx.conf
└── README.md
```

---

## 🏁 Getting Started

### 1. Backend Setup

```bash
cd backend

# Create virtual environment
python -m venv venv
source venv/bin/activate  # or venv\Scripts\activate on Windows

# Install dependencies
pip install -r requirements.txt

# Copy env file and configure
cp .env.example .env

# Train ML model
python ml/train_model.py

# Run server
uvicorn main:app --reload --host 0.0.0.0 --port 8000
```

API docs available at: `http://localhost:8000/docs`

### 2. Android Setup

1. Open `android/` folder in Android Studio
2. Update `API_BASE_URL` in `app/build.gradle.kts` to your backend URL
3. Update `API_KEY` to match your backend API key
4. Build and run on device/emulator (min SDK 24)

### 3. Docker Deployment

```bash
# Build and run
docker-compose up -d

# Check logs
docker-compose logs -f api
```

---

## 🌐 API Reference

### POST /check-link

Scan a URL for threats.

**Request:**
```json
{
  "url": "http://paytm-verify-login.com/offer",
  "device_id": "optional-device-id"
}
```

**Response:**
```json
{
  "url": "http://paytm-verify-login.com/offer",
  "risk_score": 87.3,
  "status": "Phishing",
  "confidence": 92.1,
  "ml_prediction": "Phishing",
  "ml_confidence": 94.5,
  "domain_age_days": 14,
  "ssl_valid": false,
  "impersonation_risk": true,
  "impersonation_target": "paytm.com",
  "suspicious_keywords": ["verify", "login", "offer"],
  "recommendations": [
    "⚠️ DO NOT click this link!",
    "🎭 This URL may be impersonating paytm.com"
  ],
  "scanned_at": "2026-02-19T14:30:00"
}
```

### GET /health
Health check endpoint.

### GET /scan-history
Get scan history (requires API key).

### GET /scan/{scan_id}
Get detailed scan result by ID.

---

## 🔐 Security

- **API Key Authentication** — All endpoints require `X-API-Key` header
- **Rate Limiting** — 30 requests/minute per IP
- **Input Validation** — Pydantic schema validation
- **CORS Control** — Configurable allowed origins
- **HTTPS** — Nginx reverse proxy with SSL

---

## 📊 Risk Scoring Weights

| Component | Weight |
|---|---|
| ML Model Prediction | 35% |
| Domain Age Analysis | 15% |
| SSL Certificate Check | 10% |
| Brand Impersonation | 15% |
| URL Structural Features | 10% |
| Google Safe Browsing | 15% |

**Score Ranges:**
- 0-39: ✅ **Safe**
- 40-69: ⚠️ **Suspicious**
- 70-100: 🚨 **Phishing**

---

## 📈 Future Enhancements

- [ ] Admin Dashboard (Web Panel)
- [ ] Analytics & reporting
- [ ] Community report feature
- [ ] Browser extension
- [ ] Push notifications for high-risk detection
- [ ] Real Kaggle dataset integration
- [ ] Multi-language support

---

## 📄 License

This project is built for educational / hackathon purposes.
