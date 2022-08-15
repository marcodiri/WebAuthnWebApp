from enum import unique
import uuid
from django.db import models
from django.contrib.auth.models import AbstractBaseUser, BaseUserManager
from django.contrib.auth.validators import ASCIIUsernameValidator


# User model with fields corresponding to webauthn.helpers.structs.PublicKeyCredentialUserEntity
# and VerifiedRegistration returned by verify_registration_response()


# class TempSessionManager(BaseUserManager):
#     def create_user(self, username, password=None):
#         if not username:
#             raise ValueError('Users must have an username')

#         user = self.model(
#             id=uuid.uuid4,
#             username=username,
#         )

#         user.set_password(password)
#         user.save(using=self._db)
#         return user

#     def create_superuser(self, username, password=None):
#         return self.create_user(username, password)


class User(AbstractBaseUser):
    id = models.UUIDField(primary_key=True, editable=False)
    username = models.CharField(unique=True, max_length=10, validators=[ASCIIUsernameValidator])
    creation_time = models.DateTimeField(auto_now_add=True)

    USERNAME_FIELD = 'id'
    
    objects = BaseUserManager()

    def __str__(self):
        return '%s | %s' % (self.id, self.username)
    
    
class TempSession(User):
    pass


class Credential(models.Model):
    user = models.ForeignKey(
        'User',
        on_delete=models.CASCADE,
    )
    credential_id = models.TextField(primary_key=True)
    credential_public_key = models.TextField(unique=True)
    
    def __str__(self):
        return '%s | %s | %s' % (self.user, self.credential_id, self.credential_public_key)
