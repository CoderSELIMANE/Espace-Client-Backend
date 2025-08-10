from django.db import models
from django.contrib.auth.models import AbstractUser
from django.contrib.auth.models import BaseUserManager
import os


class CustomUserManager(BaseUserManager):
    """Manager personnalisé pour le modèle utilisateur avec email comme identifiant"""
    
    def create_user(self, email, password=None, **extra_fields):
        if not email:
            raise ValueError('L\'email est obligatoire')
        email = self.normalize_email(email)
        user = self.model(email=email, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user
    
    def create_superuser(self, email, password=None, **extra_fields):
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)
        
        if extra_fields.get('is_staff') is not True:
            raise ValueError('Le superuser doit avoir is_staff=True.')
        if extra_fields.get('is_superuser') is not True:
            raise ValueError('Le superuser doit avoir is_superuser=True.')
        
        return self.create_user(email, password, **extra_fields)


class CustomUser(AbstractUser):
    """Modèle utilisateur personnalisé avec email comme identifiant"""

    username = None  # Supprimer le champ username
    email = models.EmailField('Email', unique=True)
    first_name = models.CharField('Prénom', max_length=30, blank=True)
    last_name = models.CharField('Nom', max_length=30, blank=True)
    phone_number = models.CharField('Numéro de téléphone', max_length=20, blank=True, help_text='Format: +33123456789 ou 0123456789')
    date_joined = models.DateTimeField('Date d\'inscription', auto_now_add=True)
    is_active = models.BooleanField('Actif', default=True)
    
    objects = CustomUserManager()
    
    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = []
    
    class Meta:
        verbose_name = 'Utilisateur'
        verbose_name_plural = 'Utilisateurs'
    
    def __str__(self):
        return self.email
    
    @property
    def full_name(self):
        return f"{self.first_name} {self.last_name}".strip()


def document_upload_path(instance, filename):
    """Fonction pour définir le chemin d'upload des documents"""
    if getattr(instance, 'is_public', False):
        return f'documents/public/{filename}'
    return f'documents/user_{instance.user.id}/{filename}'


class Document(models.Model):
    """Modèle pour les documents des utilisateurs"""
    
    DOCUMENT_TYPES = [
        ('pdf', 'PDF'),
        ('fiche', 'Fiche'),
        ('image', 'Image'),
        ('other', 'Autre'),
    ]
    
    user = models.ForeignKey(CustomUser, on_delete=models.CASCADE, related_name='documents')
    title = models.CharField('Titre', max_length=200)
    description = models.TextField('Description', blank=True)
    file = models.FileField('Fichier', upload_to=document_upload_path)
    document_type = models.CharField('Type de document', max_length=20, choices=DOCUMENT_TYPES, default='other')
    uploaded_at = models.DateTimeField('Date d\'upload', auto_now_add=True)
    updated_at = models.DateTimeField('Dernière modification', auto_now=True)
    is_active = models.BooleanField('Actif', default=True)
    is_public = models.BooleanField('Document public', default=False, help_text='Si coché, le document sera visible par tous les utilisateurs')
    
    class Meta:
        verbose_name = 'Document'
        verbose_name_plural = 'Documents'
        ordering = ['-uploaded_at']
    
    def __str__(self):
        return f"{self.title} - {self.user.email}"
    
    @property
    def file_size(self):
        """Retourne la taille du fichier en bytes"""
        try:
            return self.file.size
        except:
            return 0
    
    @property
    def file_extension(self):
        """Retourne l'extension du fichier"""
        return os.path.splitext(self.file.name)[1].lower()
    
    def delete(self, *args, **kwargs):
        """Supprimer le fichier physique lors de la suppression du modèle"""
        if self.file:
            if os.path.isfile(self.file.path):
                os.remove(self.file.path)
        super().delete(*args, **kwargs)
