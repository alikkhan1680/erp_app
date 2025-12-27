from rest_framework.exceptions import PermissionDenied
from .models import CustomUser



class UserService:

    @staticmethod
    def update_existing_user(**data):
        """
        OTP orqali yaratilgan userni topib update qiladi.
        Agar topilmasa, xatolik beradi.
        """
        primary_mobile = data.get("primary_mobile")
        user = CustomUser.objects.filter(primary_mobile=primary_mobile).first()

        if not user:
            raise ValueError("OTP orqali ro'yxatdan o'tmagan foydalanuvchi")

        password = data.pop("password", None)

        # Mavjud userni update qilish (final signup)
        for key, value in data.items():
            setattr(user, key, value)

        if password:
            user.set_password(password)
        user.save()

        return user


class RoleService:

    @staticmethod
    def change_user_role(actor_user, target_user_id, new_role):
        target_user = CustomUser.objects.get(id=target_user_id)

        # permission tekshiruvi
        role_hierarchy = {
            "account_owner": 4,
            "admin": 3,
            "manager": 2,
            "employee": 1
        }

        if role_hierarchy.get(actor_user.user_role, 0) <= role_hierarchy.get(target_user.user_role, 0):
            raise PermissionDenied("Siz bu foydalanuvchining ro'lini ozgartira olmaysiz")


        old_role = target_user.user_role
        target_user.user_role = new_role
        target_user.save()

        from .models import RoleChangeLog
        RoleChangeLog.objects.create(
            user=target_user,
            old_role=old_role,
            new_role=new_role,
            changed_by=actor_user
        )

        return target_user
