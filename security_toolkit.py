"""
Security Toolkit — صندوق أدوات الأمان
=======================================
أداة طرفية (CLI) شاملة تضم:
    1) توليد كلمة مرور قوية عشوائيًا
    2) فحص قوة كلمة مرور
    3) تشفير ملف بكلمة مرور (AES عبر Fernet + PBKDF2)
    4) فك تشفير ملف
    5) حساب بصمة SHA-256 للتحقق من سلامة الملف

يتطلب مكتبة cryptography:
    pip install cryptography --break-system-packages
"""

import os
import re
import base64
import hashlib
import getpass
import secrets
import string

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# ─────────────────────────────────────────────
# ثوابت
# ─────────────────────────────────────────────
COMMON_PASSWORDS = {
    "123456", "password", "123456789", "12345678", "qwerty",
    "abc123", "111111", "123123", "letmein", "admin", "welcome",
}
SPECIAL_CHARS = "@#$%^&*+=!-_.?/\\|~`{}[]:;\"'<>,()"
SALT_SIZE = 16          # بايت
KDF_ITERATIONS = 480_000  # توصية OWASP الحالية لـ PBKDF2-HMAC-SHA256


# ─────────────────────────────────────────────
# 1) توليد كلمة مرور قوية
# ─────────────────────────────────────────────
def generate_password(length: int = 16) -> str:
    """
    يولّد كلمة مرور عشوائية آمنة (باستخدام secrets، وليس random العادية)
    مع ضمان وجود حرف كبير وصغير ورقم ورمز خاص على الأقل.
    """
    if length < 8:
        length = 8  # حد أدنى معقول

    pools = [
        string.ascii_lowercase,
        string.ascii_uppercase,
        string.digits,
        SPECIAL_CHARS,
    ]

    # نضمن وجود نوع واحد على الأقل من كل مجموعة
    password_chars = [secrets.choice(pool) for pool in pools]

    all_chars = "".join(pools)
    remaining = length - len(password_chars)
    password_chars += [secrets.choice(all_chars) for _ in range(remaining)]

    # نخلط الترتيب حتى لا تكون الأحرف المضمونة دائمًا في البداية
    secrets.SystemRandom().shuffle(password_chars)
    return "".join(password_chars)


# ─────────────────────────────────────────────
# 2) فحص قوة كلمة المرور
# ─────────────────────────────────────────────
def check_password_strength(password: str):
    """
    يعيد (score, label, tips):
        score : من 0 إلى 5
        label : تصنيف نصي
        tips  : قائمة اقتراحات للتحسين
    """
    tips = []
    score = 0

    if not password:
        return 0, "غير صالحة", ["كلمة المرور فارغة."]

    if len(password) >= 12:
        score += 2
    elif len(password) >= 8:
        score += 1
        tips.append("يُفضّل استخدام 12 حرفًا أو أكثر لأمان أعلى.")
    else:
        tips.append("يجب أن تحتوي على 8 أحرف على الأقل.")

    if re.search(r"[a-z]", password) and re.search(r"[A-Z]", password):
        score += 1
    else:
        tips.append("أضف مزيجًا من الأحرف الكبيرة والصغيرة (A-Z, a-z).")

    if re.search(r"[0-9]", password):
        score += 1
    else:
        tips.append("أضف رقمًا واحدًا على الأقل (0-9).")

    if re.search(f"[{re.escape(SPECIAL_CHARS)}]", password):
        score += 1
    else:
        tips.append("أضف رمزًا خاصًا واحدًا على الأقل (مثل @ # $ % ^ & *).")

    if password.lower() in COMMON_PASSWORDS:
        score = 0
        tips.insert(0, "هذه كلمة مرور شائعة جدًا وسهلة التخمين، تجنّبها تمامًا.")

    if re.search(r"(.)\1{3,}", password):
        score = max(0, score - 1)
        tips.append("تجنّب تكرار نفس الحرف أكثر من 3 مرات متتالية.")

    score = max(0, min(score, 5))

    if score <= 1:
        label = "ضعيفة"
    elif score <= 3:
        label = "متوسطة"
    elif score == 4:
        label = "جيدة"
    else:
        label = "قوية جدًا"

    return score, label, tips


# ─────────────────────────────────────────────
# مساعد داخلي: اشتقاق مفتاح تشفير من كلمة المرور
# ─────────────────────────────────────────────
def _derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=KDF_ITERATIONS,
    )
    key = kdf.derive(password.encode("utf-8"))
    return base64.urlsafe_b64encode(key)


# ─────────────────────────────────────────────
# 3) تشفير ملف
# ─────────────────────────────────────────────
def encrypt_file(input_path: str, password: str) -> str:
    """
    يشفّر الملف المُعطى بكلمة مرور، وينشئ ملفًا جديدًا بامتداد .enc
    يحتوي على: [salt (16 بايت)] + [البيانات المشفّرة].
    """
    if not os.path.exists(input_path):
        raise FileNotFoundError("الملف غير موجود.")
    if not password:
        raise ValueError("كلمة المرور فارغة.")

    salt = secrets.token_bytes(SALT_SIZE)
    key = _derive_key(password, salt)
    fernet = Fernet(key)

    with open(input_path, "rb") as f:
        data = f.read()

    encrypted = fernet.encrypt(data)
    output_path = input_path + ".enc"

    with open(output_path, "wb") as f:
        f.write(salt + encrypted)

    return output_path


# ─────────────────────────────────────────────
# 4) فك تشفير ملف
# ─────────────────────────────────────────────
def decrypt_file(input_path: str, password: str) -> str:
    """
    يفك تشفير ملف تم تشفيره بواسطة encrypt_file.
    يتوقع أن يبدأ الملف بـ salt (16 بايت) ثم البيانات المشفّرة.
    """
    if not os.path.exists(input_path):
        raise FileNotFoundError("الملف غير موجود.")
    if not password:
        raise ValueError("كلمة المرور فارغة.")

    with open(input_path, "rb") as f:
        raw = f.read()

    if len(raw) < SALT_SIZE:
        raise ValueError("الملف تالف أو ليس ملفًا مشفّرًا صحيحًا.")

    salt, token = raw[:SALT_SIZE], raw[SALT_SIZE:]
    key = _derive_key(password, salt)
    fernet = Fernet(key)

    try:
        decrypted = fernet.decrypt(token)
    except InvalidToken:
        raise ValueError("كلمة المرور غير صحيحة أو الملف تالف.")

    if input_path.endswith(".enc"):
        output_path = input_path[:-4]
    else:
        output_path = input_path + ".dec"

    with open(output_path, "wb") as f:
        f.write(decrypted)

    return output_path


# ─────────────────────────────────────────────
# 5) التحقق من سلامة الملفات (SHA-256)
# ─────────────────────────────────────────────
def file_hash(path: str) -> str:
    if not os.path.exists(path):
        raise FileNotFoundError("الملف غير موجود.")
    sha256 = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            sha256.update(chunk)
    return sha256.hexdigest()


# ─────────────────────────────────────────────
# القائمة التفاعلية
# ─────────────────────────────────────────────
def menu() -> str:
    print("\n" + "═" * 46)
    print(" 🔐 Security Toolkit — صندوق أدوات الأمان")
    print("═" * 46)
    print("1) توليد كلمة مرور قوية")
    print("2) فحص قوة كلمة مرور")
    print("3) تشفير ملف")
    print("4) فك تشفير ملف")
    print("5) بصمة SHA-256 لملف (للتحقق من السلامة)")
    print("0) خروج")
    return input("اختر رقم: ").strip()


def main() -> None:
    while True:
        choice = menu()

        if choice == "1":
            try:
                length = int(input("طول كلمة المرور (افتراضي 16): ") or 16)
            except ValueError:
                length = 16
            pwd = generate_password(length=length)
            print(f"\n🔑 كلمة المرور المولّدة: {pwd}")
            score, label, _ = check_password_strength(pwd)
            print(f"   التقييم: {label} ({score}/5)")

        elif choice == "2":
            pwd = getpass.getpass("أدخل كلمة المرور (لن تظهر أثناء الكتابة): ")
            score, label, tips = check_password_strength(pwd)
            print(f"\n📊 التقييم: {label} ({score}/5)")
            if tips:
                print("💡 اقتراحات للتحسين:")
                for t in tips:
                    print(f"   - {t}")

        elif choice == "3":
            path = input("مسار الملف المراد تشفيره: ").strip()
            pwd = getpass.getpass("كلمة المرور للتشفير: ")
            pwd2 = getpass.getpass("أعد كتابة كلمة المرور: ")
            if pwd != pwd2:
                print("❌ كلمتا المرور غير متطابقتين.")
                continue
            try:
                out = encrypt_file(path, pwd)
                print(f"✅ تم التشفير بنجاح: {out}")
            except Exception as e:
                print(f"❌ خطأ: {e}")

        elif choice == "4":
            path = input("مسار الملف المشفّر (.enc): ").strip()
            pwd = getpass.getpass("كلمة المرور لفك التشفير: ")
            try:
                out = decrypt_file(path, pwd)
                print(f"✅ تم فك التشفير بنجاح: {out}")
            except Exception as e:
                print(f"❌ خطأ: {e}")

        elif choice == "5":
            path = input("مسار الملف: ").strip()
            try:
                h = file_hash(path)
                print(f"🔎 SHA-256: {h}")
            except Exception as e:
                print(f"❌ خطأ: {e}")

        elif choice == "0":
            print("مع السلامة 👋")
            break

        else:
            print("خيار غير صحيح، حاول مرة ثانية.")


if __name__ == "__main__":
    main()