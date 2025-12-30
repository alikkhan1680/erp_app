# from django.utils import timezone
# import hashlib
# import pyotp
#
# class TwoFAService:
#     @staticmethod
#     def generate_secret():
#         return pyotp.random_base32()
#
#
#     @staticmethod
#     def generate_qr_uri(user_email, secret, app_name="MyApp"):
#         totp = pyotp.TOTP(secret)
#         return totp.provisioning_uri(name=user_email, issuer_name=app_name)
#
#
#     @staticmethod
#     def verify_totp_code(secret, code):
#         totp = pyotp.TOTP(secret)
#         return totp.verify(code)  # True | False
#
#     @staticmethod
#     def enable_2fa(user, code):
#
#         if not user.two_fa_secret:
#             return False, "No 2FA secret set"
#
#         # kodni tekshirish
#         valid = TwoFAService.verify_totp_code(user.two_fa_secret, code)
#         if not valid:
#             return False,
#
#         # enable qilamiz
#         user.is_2fa_enabled = True
#         user.last_2fa_verified_at = timezone.now()
#
#         # backup codes yaratamiz
#         backup_codes = TwoFAService.generate_backup_codes()
#         # hashed qilib saqlaymiz
#         user.backup_codes = [hashlib.sha256(c.encode()).hexdigest() for c in backup_codes]
#
#         user.save(update_fields=["is_2fa_enabled", "backup_codes", "last_2fa_verified_at"])
#         return True, backup_codes
#
#     @staticmethod
#     def generate_backup_codes(count=5):
#         import secrets, string
#         codes = []
#         for _ in range(count):
#             code = ''.join(secrets.choice(string.ascii_uppercase + string.digits) for _ in range(8))
#             codes.append(code)
#         return codes
#
#
