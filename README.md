# 📄 סורק חשבוניות Gmail — יפתח גפן

סורק אוטומטי שמאתר חשבוניות בתיבת ה-Gmail שלך מתאריך מסוים ועד היום.

---

## 🚀 הגדרה ראשונה (פעם אחת בלבד)

### שלב 1 — התקנת Python
ודא ש-Python 3.10+ מותקן: `python --version`

### שלב 2 — התקנת ספריות
```bash
cd invoice-scanner
pip install -r requirements.txt
```

### שלב 3 — הגדרת Google Cloud

1. היכנס ל: https://console.cloud.google.com
2. צור פרויקט חדש (או השתמש בקיים)
3. הפעל את **Gmail API**:
   - APIs & Services → Library → חפש "Gmail API" → Enable
4. צור OAuth Credentials:
   - APIs & Services → Credentials → Create Credentials → OAuth 2.0 Client ID
   - Application type: **Desktop app** (שם: "Invoice Scanner")
   - לחץ Create → הורד JSON
5. שנה שם הקובץ ל: `credentials.json`
6. העבר אותו לתיקיית `invoice-scanner/`
7. ב-OAuth consent screen — הוסף את האימייל שלך כ-Test User

### שלב 4 — הגדרת Anthropic API
האפליקציה משתמשת ב-Claude לניתוח מיילים.

הגדר את משתנה הסביבה:
```bash
# Mac/Linux:
export ANTHROPIC_API_KEY="sk-ant-..."

# Windows:
set ANTHROPIC_API_KEY=sk-ant-...
```

---

## ▶️ הפעלה

```bash
cd invoice-scanner
python app.py
```

פתח דפדפן: http://localhost:5050

---

## 📋 שימוש

1. **התחבר לגוגל** — לחץ "התחבר עם Google" ואשר הרשאות
2. **הגדר תאריך** — בחר מאיזה תאריך לסרוק
3. **הפעל סריקה** — לחץ "התחל סריקה" והמתן
4. **הורד קבצים** — הורד חשבוניות בודדות או את כולן כ-ZIP

---

## 🔍 מה הסורק מחפש

- קבצים מצורפים: PDF, PNG עם שמות כמו "חשבונית", "invoice", "receipt"
- מילות מפתח בנושא ובגוף המייל (עברית ואנגלית)
- ניתוח AI עם Claude לזיהוי חכם
- **מסנן:** רק חשבוניות על שם יפתח גפן (מדלג על רעות אגם)
- לינקים לחשבוניות חיצוניות

---

## 📁 קבצים מורדים

נשמרים בתיקיית `downloads/` עם שמות ברורים לפי תאריך ונושא.

---

## ⚠️ פתרון בעיות

**שגיאת "redirect_uri_mismatch":**
ב-Google Cloud Console → Credentials → ערוך את OAuth Client → הוסף:
`http://localhost:5050/oauth_callback`

**Token פג תוקף:**
מחק את קובץ `token.pickle` והתחבר מחדש.
