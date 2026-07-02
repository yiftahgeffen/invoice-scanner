import os
import json
import base64
import re
import pickle
import threading
import secrets
from datetime import datetime, date
from pathlib import Path
from flask import Flask, render_template, request, jsonify, send_file, redirect, url_for, session
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import Flow
from google.auth.transport.requests import Request
from googleapiclient.discovery import build
import anthropic

ANTHROPIC_API_KEY_VALUE = os.environ.get('ANTHROPIC_API_KEY', '')

def load_env():
    if ANTHROPIC_API_KEY_VALUE:
        print(f"✅ API Key נטען ({ANTHROPIC_API_KEY_VALUE[:15]}...)")
        return
    base = os.path.dirname(os.path.abspath(__file__))
    for filename in ['.env', 'env.txt', 'env_.txt', '.env.txt', 'env..txt']:
        env_file = os.path.join(base, filename)
        if os.path.exists(env_file):
            with open(env_file, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#') and '=' in line:
                        key, val = line.split('=', 1)
                        os.environ[key.strip()] = val.strip().strip('"').strip("'")
            global ANTHROPIC_API_KEY_VALUE
            ANTHROPIC_API_KEY_VALUE = os.environ.get('ANTHROPIC_API_KEY', '')
            print(f"✅ נטען קובץ: {filename}")
            return
    print("⚠️ API Key לא הוגדר!")

load_env()

def ensure_credentials():
    if not os.path.exists(CLIENT_SECRETS_FILE):
        creds_json = os.environ.get('GOOGLE_CREDENTIALS_JSON')
        if creds_json:
            with open(CLIENT_SECRETS_FILE, 'w') as f:
                f.write(creds_json)
            print("✅ credentials.json נוצר מ-env var")

app = Flask(__name__)
app.secret_key = os.environ.get('FLASK_SECRET_KEY', 'invoice-scanner-secret-key-2024')

SCOPES = ['https://www.googleapis.com/auth/gmail.readonly']

# Yiftach's own email addresses - emails SENT by these are always outgoing, skip them
OWN_EMAIL_ADDRESSES = [
    'yiftahgeffen@gmail.com',
    'yiftah.geffen@',
    'yiftahgeffen@',
]

DATA_DIR = Path(os.environ.get('DATA_DIR', os.path.dirname(os.path.abspath(__file__))))
CLIENT_SECRETS_FILE = str(DATA_DIR / 'credentials.json')
TOKEN_FILE = str(DATA_DIR / 'token.pickle')
DOWNLOADS_DIR = DATA_DIR / 'downloads'
DOWNLOADS_DIR.mkdir(exist_ok=True)
RESULTS_FILE = str(DATA_DIR / 'scan_results.json')
FEEDBACK_FILE = str(DATA_DIR / 'feedback.json')
RULES_FILE = str(DATA_DIR / 'blocking_rules.json')

ensure_credentials()

def load_feedback():
    if os.path.exists(FEEDBACK_FILE):
        with open(FEEDBACK_FILE, 'r', encoding='utf-8') as f:
            return json.load(f)
    return {'confirmed': [], 'rejected': []}

def save_feedback(data):
    with open(FEEDBACK_FILE, 'w', encoding='utf-8') as f:
        json.dump(data, f, ensure_ascii=False, indent=2)

def load_rules():
    if os.path.exists(RULES_FILE):
        with open(RULES_FILE, 'r', encoding='utf-8') as f:
            return json.load(f)
    return {'blocked_senders': [], 'blocked_keywords': [], 'ignored_emails': []}

def save_rules(data):
    with open(RULES_FILE, 'w', encoding='utf-8') as f:
        json.dump(data, f, ensure_ascii=False, indent=2)

scan_state = {
    'running': False,
    'progress': 0,
    'total': 0,
    'current_email': '',
    'found_invoices': [],
    'suspicious_emails': [],
    'processed': 0,
    'error': None,
    'done': False,
    'log': []
}

def get_credentials():
    creds = None
    if os.path.exists(TOKEN_FILE):
        with open(TOKEN_FILE, 'rb') as token:
            creds = pickle.load(token)
    elif os.environ.get('GOOGLE_TOKEN_B64'):
        # Restore token from environment variable (used on Render free tier - no persistent disk)
        token_data = base64.b64decode(os.environ['GOOGLE_TOKEN_B64'])
        with open(TOKEN_FILE, 'wb') as f:
            f.write(token_data)
        with open(TOKEN_FILE, 'rb') as token:
            creds = pickle.load(token)
    if creds and creds.expired and creds.refresh_token:
        creds.refresh(Request())
        with open(TOKEN_FILE, 'wb') as token:
            pickle.dump(creds, token)
    return creds

def save_credentials(creds):
    with open(TOKEN_FILE, 'wb') as token:
        pickle.dump(creds, token)

def log(msg):
    scan_state['log'].append(f"[{datetime.now().strftime('%H:%M:%S')}] {msg}")
    print(msg)

# Keywords that indicate an INCOMING invoice/receipt (expenses the user paid)
INVOICE_KEYWORDS_HE = [
    'חשבונית', 'קבלה', 'הודעת חיוב', 'חיוב חודשי', 'חיוב שנתי',
    'מסמך כספי', 'אישור תשלום', 'אישור רכישה', 'תודה על רכישתך',
    'תודה על קנייתך', 'רכישה בוצעה', 'חשבונית מס', 'סכום לתשלום',
    'סה"כ לתשלום', 'חשבון לתשלום', 'פרטי החיוב', 'נחייב אותך',
    'חויבת', 'חויב חשבונך'
]

INVOICE_KEYWORDS_EN = [
    'invoice', 'receipt', 'billing', 'payment confirmation',
    'purchase confirmation', 'thank you for your purchase',
    'thank you for your order', 'payment receipt',
    'tax invoice', 'charge confirmation',
    'subscription receipt', 'transaction receipt', 'your invoice',
    'invoice attached', 'download invoice',
    'view invoice', 'download receipt', 'view receipt',
    'you have been charged', 'your payment', 'your subscription',
    'your account has been charged'
]

# Patterns that indicate the email is NOT an incoming invoice
EXCLUDE_EMAIL_PATTERNS = [
    # Promotional markers
    r'\[פרסומת\]', r'\[promotion\]', r'\[promo\]', r'unsubscribe',
    r'להסרה מרשימת', r'ביטול הרשמה',
    # Security / account alerts
    r'התראת אבטחה', r'security alert', r'sign.?in attempt',
    r'new sign.?in', r'כניסה חדשה', r'אימות דו.?שלבי',
    r'verification code', r'קוד אימות', r'reset your password',
    r'איפוס סיסמה',
    # Events / conferences / newsletters
    r'וובינר', r'webinar', r'ניוזלטר', r'newsletter',
    r'עדכון שבועי', r'weekly update', r'הרשמה לאירוע',
    # Shipping / delivery / order status (NOT billing)
    r'מידע בנוגע להזמנת', r'your order (is|has|status)',
    r'המשלוח שלך', r'out for delivery', r'נמסר', r'מעקב משלוח',
    r'ממתינים עבורך בסניף', r'לאיסוף ההזמנה', r'הזמנה מוכנה',
    r'order (is )?ready', r'ready for (pickup|collection)',
    # Purchase orders
    r'הזמנת רכש', r'purchase order', r'\bP\.?O\.?\b',
    # Travel & marketing
    r'לאן תטיילו', r'book your (flight|hotel|trip)',
    # Welcome / onboarding emails (payment mentioned but no actual invoice)
    r'welcome to (the|your|our|a)\s', r'ברוך הבא לתוכנית',
    r'thanks for (starting|joining) your',
]

# Patterns in email body that indicate this is an order confirmation, NOT the invoice itself
BODY_EXCLUDE_PATTERNS = [
    r'מזהה\s*הזמנה',           # "Order ID" in body = order confirmation email
    r'\border\s+id\s*[\n:]',   # Same in English
    r'עיין בחשבונית שלך כדי',  # "See your invoice to see the final amount" = invoice is elsewhere
]

# Keywords that are STRONG indicators of an incoming invoice (expense)
# Only these will trigger the invoice check - not weak words like "תשלום" alone
STRONG_INVOICE_INDICATORS_HE = [
    'חשבונית',              # Any invoice mention in subject is enough
    'מצורפת חשבונית',      # Attached invoice
    'חשבונית מס',           # Tax invoice
    'החשבונית החודשית',     # Monthly invoice (כביש 6, חשמל, מים...)
    'החשבונית שלך',         # Your invoice
    'חשבונית דיגיטלית',    # Digital invoice
    'החשבונית הדיגיטלית',  # Digital invoice arrived
    'לצפייה בחשבונית',     # View invoice link
    'החשבונית הגיעה',       # Invoice arrived
    'חשבונית חדשה',         # New invoice
    'קבלה על סך',           # Receipt with amount
    'אישור חיוב',           # Charge confirmation
    'הודעת חיוב',           # Billing notice
    'חיוב חודשי',           # Monthly charge
    'חיוב שנתי',            # Annual charge
    'חייבנו אותך',          # We charged you
    'חויב חשבונך',          # Your account was charged
    'פרטי החיוב שלך',       # Your billing details
    'חשבונית צורפה',        # Invoice attached
]

STRONG_INVOICE_INDICATORS_EN = [
    'your invoice',
    'invoice attached',
    'payment receipt',
    'you have been charged',
    'your account has been charged',
    'your subscription',
    'billing confirmation',
    'charge confirmation',
    'transaction receipt',
    'your payment was',
    'tax invoice',
]

# Patterns that indicate this is an OUTGOING invoice (issued BY the user)
# We do NOT want these - Yiftach issued them, they are income invoices
OUTGOING_INVOICE_PATTERNS = [
    # Invoice issued BY Yiftach Gefen TO a client
    r'(?:חשבונית|invoice).*(?:מאת|from|by)\s*(?:יפתח\s*גפן|yiftah?\s*gaf?en)',
    r'(?:יפתח\s*גפן|yiftah?\s*gaf?en).*(?:לכבוד|to|to:)',
    # Subject patterns like "חשבונית מס 20027 מאת יפתח גפן"
    r'חשבונית.*מאת.*(?:יפתח|גפן)',
    r'invoice.*from.*(?:yiftah?|gafen)',
]

INVOICE_FILE_PATTERNS = [
    r'invoice', r'receipt', r'חשבונית', r'קבלה', r'bill',
    r'חשבון', r'payment', r'תשלום', r'order.*confirm', r'אישור'
]

TARGET_NAME_PATTERNS = [
    r'יפתח\s*גפן', r'yiftach\s*gafen', r'yiftah\s*gafen',
    r'גפן\s*יפתח', r'gafen\s*yiftach', r'gafen\s*yiftah'
]

EXCLUDE_NAME_PATTERNS = [
    r'רעות\s*אגם', r'raaut\s*agam', r'reut\s*agam', r'agam\s*reut'
]

def is_invoice_filename(filename):
    if not filename:
        return False
    fn_lower = filename.lower()
    for pat in INVOICE_FILE_PATTERNS:
        if re.search(pat, fn_lower, re.IGNORECASE):
            return True
    ext = fn_lower.split('.')[-1] if '.' in fn_lower else ''
    return ext in ['pdf', 'png', 'jpg', 'jpeg'] and any(
        re.search(pat, fn_lower, re.IGNORECASE) for pat in INVOICE_FILE_PATTERNS
    )

def contains_invoice_keywords(text):
    if not text:
        return False, []
    text_lower = text.lower()
    found = []
    for kw in INVOICE_KEYWORDS_HE + INVOICE_KEYWORDS_EN:
        if kw.lower() in text_lower:
            found.append(kw)
    return len(found) > 0, found

def check_target_name(text):
    if not text:
        return None
    for pat in EXCLUDE_NAME_PATTERNS:
        if re.search(pat, text, re.IGNORECASE):
            return 'exclude'
    for pat in TARGET_NAME_PATTERNS:
        if re.search(pat, text, re.IGNORECASE):
            return 'include'
    return None

def extract_invoice_links(text):
    if not text:
        return []
    link_patterns = [
        r'https?://[^\s<>"]+(?:invoice|receipt|bill|חשבונית|קבלה|download|pdf)[^\s<>"]*',
        r'https?://[^\s<>"]*(?:invoice|receipt|חשבונית|קבלה)[^\s<>"]*',
    ]
    links = []
    for pat in link_patterns:
        links.extend(re.findall(pat, text, re.IGNORECASE))
    return list(set(links))

def get_email_body(msg_data):
    body_text = ''
    body_html = ''

    def extract_parts(parts):
        nonlocal body_text, body_html
        for part in parts:
            mime = part.get('mimeType', '')
            if mime == 'text/plain':
                data = part.get('body', {}).get('data', '')
                if data:
                    body_text += base64.urlsafe_b64decode(data + '==').decode('utf-8', errors='ignore')
            elif mime == 'text/html':
                data = part.get('body', {}).get('data', '')
                if data:
                    body_html += base64.urlsafe_b64decode(data + '==').decode('utf-8', errors='ignore')
            elif 'parts' in part:
                extract_parts(part['parts'])

    payload = msg_data.get('payload', {})
    mime = payload.get('mimeType', '')

    if mime == 'text/plain':
        data = payload.get('body', {}).get('data', '')
        if data:
            body_text = base64.urlsafe_b64decode(data + '==').decode('utf-8', errors='ignore')
    elif mime == 'text/html':
        data = payload.get('body', {}).get('data', '')
        if data:
            body_html = base64.urlsafe_b64decode(data + '==').decode('utf-8', errors='ignore')
    elif 'parts' in payload:
        extract_parts(payload['parts'])

    if body_html and not body_text:
        body_text = re.sub(r'<[^>]+>', ' ', body_html)
        body_text = re.sub(r'\s+', ' ', body_text).strip()

    return body_text, body_html

def analyze_with_claude(subject, body_text, sender, attachments_info):
    client = anthropic.Anthropic(api_key=ANTHROPIC_API_KEY_VALUE)

    prompt = f"""אתה מנתח מיילים עבור יפתח גפן. המטרה: למצוא חשבוניות הוצאה בלבד — כלומר מיילים שבהם גורם חיצוני חייב את יפתח על שירות/מוצר שהוא רכש.

חוקים מחייבים:
1. אם השולח הוא יפתח גפן עצמו (yiftahgeffen@gmail.com) — is_invoice: false. תמיד.
2. אם הקובץ המצורף שמו מכיל "מאת יפתח גפן" — זו חשבונית יוצאת שיפתח הוציא ללקוח, is_invoice: false.
3. אם זו הודעת מוכנות הזמנה / איסוף מחנות (גם אם כתוב "חשבונית" בתוך תבנית טכנית) — is_invoice: false.
4. אם זו הזמנת רכש (Purchase Order) — is_invoice: false.
5. אם אין חיוב ממשי ליפתח (רק פרסום, עדכון, ניוזלטר) — is_invoice: false.
6. אם המייל הוא אישור הזמנה (order confirmation) שאומר "עיין בחשבונית שלך" / "see your invoice" ומפנה לחשבונית אחרת — is_invoice: false. החשבונית עצמה לא כאן.
7. אם המייל הוא ברכת הצטרפות ("Welcome to the Pro plan", "ברוך הבא") שמזכיר חיוב אך לא מכיל את מסמך החשבונית — is_invoice: false.
8. אנחנו רוצים: חשבוניות/קבלות שגורם אחר הוציא ליפתח על משהו שהוא שילם. אם הנושא מתחיל ב"חשבונית וקבלה" וצורף PDF — זו חשבונית, is_invoice: true גם אם "בהמשך להזמנתך" בנושא.

נושא: {subject}
שולח: {sender}
קבצים מצורפים: {attachments_info}
תוכן המייל:
{body_text[:2000]}

ענה בפורמט JSON בלבד:
{{
  "is_invoice": true/false,
  "confidence": 0-100,
  "invoice_direction": "incoming/outgoing/not_invoice",
  "reason": "הסבר קצר בעברית",
  "invoice_type": "invoice/receipt/payment_confirmation/link_to_invoice/order_status/outgoing/other"
}}"""

    try:
        response = client.messages.create(
            model="claude-haiku-4-5-20251001",
            max_tokens=500,
            messages=[{"role": "user", "content": prompt}]
        )
        text = response.content[0].text.strip()
        text = re.sub(r'```json|```', '', text).strip()
        return json.loads(text)
    except Exception as e:
        log(f"    ⚠️ Claude API שגיאה: {str(e)[:80]}")
        # Fallback: use keyword detection
        combined = (subject + " " + body_text[:1000]).lower()
        invoice_words = ['חשבונית', 'קבלה', 'invoice', 'receipt', 'תשלום', 'payment', 'חיוב', 'תודה על רכישת']
        matches = [w for w in invoice_words if w in combined]
        # Check if it looks like an outgoing invoice in subject
        outgoing_hints = ['מאת יפתח', 'from yiftah', 'חשבונית מס 2', 'לכבוד:']
        is_outgoing = any(h in combined for h in outgoing_hints)
        if is_outgoing:
            return {"is_invoice": False, "confidence": 0, "invoice_direction": "outgoing",
                    "reason": "נראה כחשבונית יוצאת", "invoice_type": "unknown"}
        confidence = min(40 + len(matches) * 15, 85) if matches else 0
        return {
            "is_invoice": len(matches) > 0,
            "confidence": confidence,
            "invoice_direction": "unknown",
            "reason": f"זוהה על ידי מילות מפתח (ללא Claude): {matches}",
            "invoice_type": "unknown"
        }

def save_attachment(service, user_id, message_id, attachment_id, filename, email_subject, email_date):
    try:
        attachment = service.users().messages().attachments().get(
            userId=user_id, messageId=message_id, id=attachment_id
        ).execute()
        data = base64.urlsafe_b64decode(attachment['data'] + '==')

        safe_subject = re.sub(r'[^\w\s-]', '', email_subject)[:40].strip()
        safe_date = email_date[:10] if email_date else 'unknown'
        safe_filename = re.sub(r'[^\w\s.-]', '', filename)

        save_path = DOWNLOADS_DIR / f"{safe_date}_{safe_subject}_{safe_filename}"
        with open(save_path, 'wb') as f:
            f.write(data)
        return str(save_path)
    except Exception as e:
        log(f"  שגיאה בשמירת קובץ {filename}: {e}")
        return None

def do_scan(start_date_str, user_email, end_date_str=None):
    global scan_state
    scan_state['running'] = True
    scan_state['done'] = False
    scan_state['found_invoices'] = []
    scan_state['suspicious_emails'] = []
    scan_state['log'] = []
    scan_state['error'] = None

    try:
        creds = get_credentials()
        service = build('gmail', 'v1', credentials=creds)

        start_date = datetime.strptime(start_date_str, '%Y-%m-%d')
        gmail_after = start_date.strftime('%Y/%m/%d')
        query = f'after:{gmail_after}'
        if end_date_str:
            end_date = datetime.strptime(end_date_str, '%Y-%m-%d')
            gmail_before = end_date.strftime('%Y/%m/%d')
            query += f' before:{gmail_before}'
        log(f"מתחיל סריקה מתאריך {start_date_str}" + (f" עד {end_date_str}" if end_date_str else ""))
        log(f"שאילתת חיפוש: {query}")

        all_message_ids = []
        page_token = None
        while True:
            kwargs = {'userId': 'me', 'q': query, 'maxResults': 500}
            if page_token:
                kwargs['pageToken'] = page_token
            result = service.users().messages().list(**kwargs).execute()
            msgs = result.get('messages', [])
            all_message_ids.extend(msgs)
            page_token = result.get('nextPageToken')
            if not page_token:
                break

        scan_state['total'] = len(all_message_ids)
        log(f"נמצאו {len(all_message_ids)} מיילים לבדיקה")

        for idx, msg_ref in enumerate(all_message_ids):
            scan_state['processed'] = idx + 1
            scan_state['progress'] = int((idx + 1) / max(len(all_message_ids), 1) * 100)

            try:
                msg_data = service.users().messages().get(
                    userId='me', id=msg_ref['id'], format='full'
                ).execute()

                headers = {h['name']: h['value'] for h in msg_data.get('payload', {}).get('headers', [])}
                subject = headers.get('Subject', '(ללא נושא)')
                sender = headers.get('From', '')
                date_str = headers.get('Date', '')
                msg_id = msg_ref['id']

                scan_state['current_email'] = f"{subject[:50]} | {sender[:30]}"

                body_text, body_html = get_email_body(msg_data)

                attachments = []
                def find_attachments(parts):
                    for part in parts:
                        filename = part.get('filename', '')
                        if filename:
                            attachments.append({
                                'filename': filename,
                                'attachment_id': part.get('body', {}).get('attachmentId'),
                                'mime': part.get('mimeType', ''),
                                'size': part.get('body', {}).get('size', 0)
                            })
                        if 'parts' in part:
                            find_attachments(part['parts'])

                payload = msg_data.get('payload', {})
                if 'parts' in payload:
                    find_attachments(payload['parts'])

                invoice_attachments = [a for a in attachments if is_invoice_filename(a['filename'])]
                attachments_info = ', '.join([a['filename'] for a in attachments]) if attachments else 'אין'

                # RULE 1: Handle emails sent by Yiftach himself
                # - Sent to HIMSELF = might be a forwarded/saved invoice → check it
                # - Sent to OTHERS = outgoing invoice to a client → skip
                sender_email = sender.lower()
                is_own_email = any(own in sender_email for own in OWN_EMAIL_ADDRESSES)
                if is_own_email:
                    recipients = headers.get('To', '') + ' ' + headers.get('Cc', '')
                    sent_to_self = any(own in recipients.lower() for own in OWN_EMAIL_ADDRESSES)
                    if not sent_to_self:
                        # Sent to someone else — outgoing invoice to client, skip
                        continue
                    # Sent to self — could be a forwarded invoice, continue checking

                # RULE 2: Check user-defined blocking rules
                rules = load_rules()
                blocked = False
                for bs in rules.get('blocked_senders', []):
                    if bs.lower() in sender.lower():
                        blocked = True
                        break
                if not blocked:
                    for bk in rules.get('blocked_keywords', []):
                        if bk.lower() in subject.lower():
                            blocked = True
                            break
                if blocked:
                    continue

                # RULE 2b: Skip specifically ignored email addresses
                for ie in rules.get('ignored_emails', []):
                    if ie.lower() in sender.lower():
                        blocked = True
                        break
                if blocked:
                    continue

                # RULE 3: Skip built-in exclusion patterns (promotions, order status, etc.)
                subject_and_sender = subject + ' ' + sender
                excluded = False
                for pat in EXCLUDE_EMAIL_PATTERNS:
                    if re.search(pat, subject_and_sender, re.IGNORECASE):
                        excluded = True
                        break
                if excluded:
                    continue

                # RULE 3b: Skip order confirmation emails (invoice is elsewhere in these)
                body_start = (body_text or '')[:500]
                for pat in BODY_EXCLUDE_PATTERNS:
                    if re.search(pat, body_start, re.IGNORECASE):
                        excluded = True
                        break
                if excluded:
                    continue

                # RULE 4: Skip outgoing invoice patterns
                is_outgoing = False
                for pat in OUTGOING_INVOICE_PATTERNS:
                    if re.search(pat, subject + ' ' + body_text[:500], re.IGNORECASE):
                        is_outgoing = True
                        break
                if is_outgoing:
                    continue

                # RULE 5: Check for STRONG invoice indicators only
                # Weak words like "תשלום", "חיוב" alone are NOT enough
                combined = subject + ' ' + body_text
                strong_found = []
                for ind in STRONG_INVOICE_INDICATORS_HE + STRONG_INVOICE_INDICATORS_EN:
                    if ind.lower() in combined.lower():
                        strong_found.append(ind)

                # Also check for invoice/receipt file attachments as a strong signal
                # If subject contains חשבונית/invoice, ANY pdf attachment counts
                subj_lower = subject.lower()
                has_invoice_word_in_subject = any(w in subj_lower for w in ['חשבונית', 'invoice', 'receipt', 'קבלה'])
                all_pdfs = [a for a in attachments if a.get('filename','').lower().endswith('.pdf')]
                if has_invoice_word_in_subject and all_pdfs:
                    invoice_attachments = invoice_attachments or all_pdfs
                has_invoice_attachment = len(invoice_attachments) > 0

                kw_found = len(strong_found) > 0 or has_invoice_attachment
                keywords = strong_found
                full_text = subject + ' ' + body_text
                name_check = check_target_name(full_text)

                if invoice_attachments or kw_found:
                    log(f"  [{idx+1}/{len(all_message_ids)}] בודק: {subject[:50]}")

                    claude_result = analyze_with_claude(subject, body_text, sender, attachments_info)

                    is_invoice = claude_result.get('is_invoice', False)
                    confidence = claude_result.get('confidence', 0)
                    invoice_direction = claude_result.get('invoice_direction', 'unknown')

                    # Hard override: subject explicitly names invoice AND attachment filename matches
                    # Handles cases like "חשבונית וקבלה מ-KSP בהמשך להזמנתך" that Claude misclassifies
                    if invoice_direction != 'outgoing' and invoice_attachments:
                        subj_has_invoice = bool(re.search(r'חשבונית|invoice', subject, re.IGNORECASE))
                        attach_has_invoice = any(
                            re.search(r'invoice|receipt|חשבונית|קבלה', att.get('filename', ''), re.IGNORECASE)
                            for att in invoice_attachments
                        )
                        if subj_has_invoice and attach_has_invoice:
                            if not is_invoice or confidence < 80:
                                log(f"    🔒 Override: נושא+שם קובץ מפורשים → חשבונית ודאית")
                            is_invoice = True
                            confidence = max(confidence, 80)

                    # Skip outgoing invoices (issued BY Yiftach to clients)
                    if invoice_direction == 'outgoing':
                        log(f"    ⏭ דלוג — חשבונית יוצאת לפי Claude")
                        continue

                    # Skip purchase orders
                    if claude_result.get('invoice_type') == 'purchase_order':
                        log(f"    ⏭ דלוג — הזמנת רכש")
                        continue

                    if name_check == 'exclude':
                        log(f"    דלוג - שם לא רלוונטי (רעות אגם)")
                        continue

                    gmail_link = f"https://mail.google.com/mail/u/0/#inbox/{msg_id}"

                    email_entry = {
                        'id': msg_id,
                        'subject': subject,
                        'sender': sender,
                        'date': date_str,
                        'gmail_link': gmail_link,
                        'confidence': confidence,
                        'keywords': keywords[:5],
                        'invoice_type': claude_result.get('invoice_type', 'unknown'),
                        'name_found': claude_result.get('name_found'),
                        'reason': claude_result.get('reason', ''),
                        'saved_files': [],
                        'invoice_links': extract_invoice_links(body_text + ' ' + body_html)
                    }

                    if is_invoice and confidence >= 50:
                        for att in invoice_attachments:
                            if att['attachment_id']:
                                saved = save_attachment(
                                    service, 'me', msg_id,
                                    att['attachment_id'], att['filename'],
                                    subject, date_str
                                )
                                if saved:
                                    email_entry['saved_files'].append({
                                        'original': att['filename'],
                                        'saved': saved
                                    })

                        if confidence >= 70 or invoice_attachments:
                            scan_state['found_invoices'].append(email_entry)
                            log(f"    ✅ נמצאה חשבונית! ביטחון: {confidence}%")
                        else:
                            scan_state['suspicious_emails'].append(email_entry)
                            log(f"    ⚠️ חשוד ({confidence}%): {subject[:40]}")
                    elif is_invoice and confidence >= 30:
                        scan_state['suspicious_emails'].append(email_entry)
                        log(f"    ⚠️ אולי חשבונית ({confidence}%): {subject[:40]}")

            except Exception as e:
                log(f"  שגיאה במייל {idx+1}: {e}")
                continue

        results = {
            'scan_date': datetime.now().isoformat(),
            'start_date': start_date_str,
            'total_scanned': len(all_message_ids),
            'found_invoices': scan_state['found_invoices'],
            'suspicious_emails': scan_state['suspicious_emails']
        }
        with open(RESULTS_FILE, 'w', encoding='utf-8') as f:
            json.dump(results, f, ensure_ascii=False, indent=2)

        log(f"\n✅ סיום! נמצאו {len(scan_state['found_invoices'])} חשבוניות ו-{len(scan_state['suspicious_emails'])} מיילים חשודים")
        scan_state['done'] = True
        scan_state['running'] = False

    except Exception as e:
        scan_state['error'] = str(e)
        scan_state['running'] = False
        scan_state['done'] = True
        log(f"❌ שגיאה כללית: {e}")
        import traceback
        traceback.print_exc()

@app.route('/')
def index():
    creds = get_credentials()
    has_auth = creds is not None and creds.valid

    results = None
    if os.path.exists(RESULTS_FILE):
        with open(RESULTS_FILE, 'r', encoding='utf-8') as f:
            results = json.load(f)

    return render_template('index.html', has_auth=has_auth, results=results)

@app.route('/auth')
def auth():
    import hashlib, base64 as b64, secrets as sec
    if not os.path.exists(CLIENT_SECRETS_FILE):
        return "קובץ credentials.json לא נמצא! ראה הוראות התקנה.", 400

    flow = Flow.from_client_secrets_file(
        CLIENT_SECRETS_FILE,
        scopes=SCOPES,
        redirect_uri=url_for('oauth_callback', _external=True)
    )
    code_verifier = sec.token_urlsafe(96)
    code_challenge = b64.urlsafe_b64encode(
        hashlib.sha256(code_verifier.encode()).digest()
    ).rstrip(b'=').decode()

    auth_url, state = flow.authorization_url(
        access_type='offline',
        include_granted_scopes='true',
        code_challenge=code_challenge,
        code_challenge_method='S256'
    )
    session['state'] = state
    session['code_verifier'] = code_verifier
    return redirect(auth_url)

@app.route('/oauth_callback')
def oauth_callback():
    state = session.get('state')
    code_verifier = session.get('code_verifier')
    flow = Flow.from_client_secrets_file(
        CLIENT_SECRETS_FILE,
        scopes=SCOPES,
        state=state,
        redirect_uri=url_for('oauth_callback', _external=True)
    )
    flow.fetch_token(
        authorization_response=request.url,
        code_verifier=code_verifier
    )
    save_credentials(flow.credentials)
    return redirect(url_for('index'))

@app.route('/scan', methods=['POST'])
def start_scan():
    global scan_state
    if scan_state['running']:
        return jsonify({'error': 'סריקה כבר רצה'}), 400

    start_date = request.json.get('start_date')
    end_date = request.json.get('end_date') or None
    if not start_date:
        return jsonify({'error': 'תאריך התחלה חסר'}), 400

    creds = get_credentials()
    if not creds or not creds.valid:
        return jsonify({'error': 'לא מחובר ל-Google'}), 401

    scan_state = {
        'running': True,
        'progress': 0,
        'total': 0,
        'current_email': '',
        'found_invoices': [],
        'suspicious_emails': [],
        'processed': 0,
        'error': None,
        'done': False,
        'log': []
    }

    thread = threading.Thread(target=do_scan, args=(start_date, 'me', end_date))
    thread.daemon = True
    thread.start()

    return jsonify({'status': 'started'})

@app.route('/status')
def get_status():
    return jsonify({
        'running': scan_state['running'],
        'progress': scan_state['progress'],
        'total': scan_state['total'],
        'processed': scan_state['processed'],
        'current_email': scan_state['current_email'],
        'found_count': len(scan_state['found_invoices']),
        'suspicious_count': len(scan_state['suspicious_emails']),
        'error': scan_state['error'],
        'done': scan_state['done'],
        'log': scan_state['log'][-20:]
    })

@app.route('/results')
def get_results():
    return jsonify({
        'found_invoices': scan_state['found_invoices'],
        'suspicious_emails': scan_state['suspicious_emails']
    })

@app.route('/download/<path:filename>')
def download_file(filename):
    file_path = Path(filename)
    if file_path.exists():
        return send_file(file_path, as_attachment=True)
    return "קובץ לא נמצא", 404

@app.route('/download_all')
def download_all():
    import zipfile
    import io

    if not scan_state['found_invoices']:
        return "אין קבצים להורדה", 404

    zip_buffer = io.BytesIO()
    with zipfile.ZipFile(zip_buffer, 'w', zipfile.ZIP_DEFLATED) as zf:
        for inv in scan_state['found_invoices']:
            for sf in inv.get('saved_files', []):
                path = Path(sf['saved'])
                if path.exists():
                    zf.write(path, path.name)

    zip_buffer.seek(0)
    return send_file(
        zip_buffer,
        mimetype='application/zip',
        as_attachment=True,
        download_name=f'invoices_{date.today()}.zip'
    )

def learn_from_feedback(feedback):
    """Use Claude to analyze patterns and auto-update blocking rules."""
    try:
        confirmed = feedback.get('confirmed_details', [])
        rejected = feedback.get('rejected_details', [])
        if len(confirmed) + len(rejected) < 3:
            return
        rules = load_rules()
        client = anthropic.Anthropic(api_key=ANTHROPIC_API_KEY_VALUE)
        prompt = f"""אתה עוזר לשפר מערכת זיהוי חשבוניות. המשתמש סימן:

מיילים שהם חשבוניות אמיתיות (צריך לזהות):
{json.dumps(confirmed[-10:], ensure_ascii=False)}

מיילים שאינם חשבוניות (צריך להתעלם):
{json.dumps(rejected[-10:], ensure_ascii=False)}

כללי חסימה קיימים: {json.dumps(rules, ensure_ascii=False)}

זהה דפוסים ברורים בלבד. ענה JSON בלבד:
{{"new_blocked_senders": [], "new_blocked_keywords": [], "insight": ""}}"""
        
        resp = client.messages.create(
            model="claude-haiku-4-5-20251001",
            max_tokens=400,
            messages=[{{"role": "user", "content": prompt}}]
        )
        text = re.sub(r'```json|```', '', resp.content[0].text).strip()
        result = json.loads(text)
        changed = False
        for s in result.get('new_blocked_senders', []):
            if s and s not in rules['blocked_senders']:
                rules['blocked_senders'].append(s)
                changed = True
        for k in result.get('new_blocked_keywords', []):
            if k and k not in rules['blocked_keywords']:
                rules['blocked_keywords'].append(k)
                changed = True
        if changed:
            save_rules(rules)
        if result.get('insight'):
            feedback['last_insight'] = result['insight']
            save_feedback(feedback)
    except Exception as e:
        print(f"Learning error: {e}")

@app.route('/feedback', methods=['POST'])
def submit_feedback():
    data = request.json
    msg_id = data.get('id')
    action = data.get('action')
    subject = data.get('subject', '')
    sender = data.get('sender', '')
    
    feedback = load_feedback()
    feedback.setdefault('confirmed_details', [])
    feedback.setdefault('rejected_details', [])
    
    detail = {'id': msg_id, 'subject': subject, 'sender': sender}
    
    if action == 'confirm':
        if msg_id not in feedback['confirmed']:
            feedback['confirmed'].append(msg_id)
            feedback['confirmed_details'].append(detail)
        if msg_id in feedback['rejected']:
            feedback['rejected'].remove(msg_id)
    elif action == 'reject':
        if msg_id not in feedback['rejected']:
            feedback['rejected'].append(msg_id)
            feedback['rejected_details'].append(detail)
        scan_state['found_invoices'] = [e for e in scan_state['found_invoices'] if e['id'] != msg_id]
        scan_state['suspicious_emails'] = [e for e in scan_state['suspicious_emails'] if e['id'] != msg_id]
    
    save_feedback(feedback)
    
    # Every 5 feedbacks, trigger AI learning in background
    total = len(feedback['confirmed']) + len(feedback['rejected'])
    if total % 5 == 0 and total > 0:
        threading.Thread(target=learn_from_feedback, args=(feedback,), daemon=True).start()
    
    return jsonify({'status': 'ok', 'total_feedback': total})

@app.route('/rules', methods=['GET'])
def get_rules():
    return jsonify(load_rules())

@app.route('/rules', methods=['POST'])
def update_rules():
    data = request.json
    rules = load_rules()
    
    action = data.get('action')
    value = data.get('value', '').strip()
    rule_type = data.get('type')  # 'sender' or 'keyword'
    
    if not value:
        return jsonify({'error': 'ערך ריק'}), 400
    
    if action == 'add':
        if rule_type == 'sender':
            key = 'blocked_senders'
        elif rule_type == 'ignored_email':
            key = 'ignored_emails'
        else:
            key = 'blocked_keywords'
        if key not in rules:
            rules[key] = []
        if value not in rules[key]:
            rules[key].append(value)
    elif action == 'remove':
        if rule_type == 'sender':
            key = 'blocked_senders'
        elif rule_type == 'ignored_email':
            key = 'ignored_emails'
        else:
            key = 'blocked_keywords'
        if key in rules:
            rules[key] = [r for r in rules[key] if r != value]
    
    save_rules(rules)
    return jsonify({'status': 'ok', 'rules': rules})

if __name__ == '__main__':
    if os.environ.get('FLASK_ENV') != 'production':
        os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'
    app.run(debug=False, port=5050)
