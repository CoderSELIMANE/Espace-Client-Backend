from rest_framework import serializers
from django.contrib.auth import authenticate
from django.contrib.auth.password_validation import validate_password
from .models import CustomUser, Document


class UserRegistrationSerializer(serializers.ModelSerializer):
    """Serializer pour l'inscription des utilisateurs"""
    
    password = serializers.CharField(write_only=True, validators=[validate_password])
    password_confirm = serializers.CharField(write_only=True)
    
    class Meta:
        model = CustomUser
        fields = ('email', 'first_name', 'last_name', 'phone_number', 'password', 'password_confirm')
    
    def validate(self, attrs):
        if attrs['password'] != attrs['password_confirm']:
            raise serializers.ValidationError("Les mots de passe ne correspondent pas.")
        return attrs
    
    def create(self, validated_data):
        validated_data.pop('password_confirm')
        user = CustomUser.objects.create_user(**validated_data)
        return user


class UserLoginSerializer(serializers.Serializer):
    """Serializer pour la connexion des utilisateurs"""
    
    email = serializers.EmailField()
    password = serializers.CharField(write_only=True)
    
    def validate(self, attrs):
        email = attrs.get('email')
        password = attrs.get('password')
        
        if email and password:
            user = authenticate(username=email, password=password)
            if not user:
                raise serializers.ValidationError('Email ou mot de passe incorrect.')
            if not user.is_active:
                raise serializers.ValidationError('Ce compte est désactivé.')
            attrs['user'] = user
        else:
            raise serializers.ValidationError('Email et mot de passe requis.')
        
        return attrs


class UserSerializer(serializers.ModelSerializer):
    """Serializer pour les informations utilisateur"""

    full_name = serializers.ReadOnlyField()

    class Meta:
        model = CustomUser
        fields = ('id', 'email', 'first_name', 'last_name', 'phone_number', 'full_name', 'date_joined',
                 'is_superuser', 'is_staff', 'is_active')
        read_only_fields = ('id', 'date_joined', 'is_superuser', 'is_staff', 'is_active')


class DocumentSerializer(serializers.ModelSerializer):
    """Serializer pour les documents"""

    file_size = serializers.ReadOnlyField()
    file_extension = serializers.ReadOnlyField()
    user_email = serializers.CharField(source='user.email', read_only=True)
    user_full_name = serializers.CharField(source='user.full_name', read_only=True)
    is_owner = serializers.SerializerMethodField()

    class Meta:
        model = Document
        fields = (
            'id', 'title', 'description', 'file', 'document_type',
            'uploaded_at', 'updated_at', 'file_size', 'file_extension',
            'user_email', 'user_full_name', 'is_active', 'is_public', 'is_owner'
        )
        read_only_fields = ('id', 'uploaded_at', 'updated_at', 'user_email', 'user_full_name', 'is_owner')

    def get_is_owner(self, obj):
        """Vérifier si l'utilisateur actuel est le propriétaire du document"""
        request = self.context.get('request')
        if request and request.user:
            return obj.user == request.user
        return False

    def create(self, validated_data):
        # Associer automatiquement l'utilisateur connecté
        validated_data['user'] = self.context['request'].user
        return super().create(validated_data)


class DocumentUploadSerializer(serializers.ModelSerializer):
    """Serializer spécialisé pour l'upload de documents"""

    class Meta:
        model = Document
        fields = ('title', 'description', 'file', 'document_type', 'is_public')

    def validate_file(self, value):
        # Limiter la taille du fichier à 10MB
        max_size = 50 * 1024 * 1024  # 10MB
        if value.size > max_size:
            raise serializers.ValidationError('La taille du fichier ne peut pas dépasser 50MB.')

        # Vérifier les extensions autorisées
        allowed_extensions = ['.pdf', '.doc', '.docx', '.txt', '.jpg', '.jpeg', '.png', '.gif']
        file_extension = value.name.split('.')[-1].lower()
        if f'.{file_extension}' not in allowed_extensions:
            raise serializers.ValidationError(
                f'Extension de fichier non autorisée. Extensions autorisées: {", ".join(allowed_extensions)}'
            )

        return value

    def validate_is_public(self, value):
        """Tous les utilisateurs peuvent créer des documents publics maintenant"""
        # Dans une bibliothèque partagée, tous les documents sont publics
        return True  # Forcer tous les documents à être publics

    def create(self, validated_data):
        validated_data['user'] = self.context['request'].user
        return super().create(validated_data)


# ========================================
# SERIALIZERS D'ADMINISTRATION
# ========================================

class AdminUserListSerializer(serializers.ModelSerializer):
    """Serializer pour la liste des utilisateurs (admin)"""

    full_name = serializers.ReadOnlyField()
    documents_count = serializers.SerializerMethodField()
    role_display = serializers.SerializerMethodField()

    class Meta:
        model = CustomUser
        fields = (
            'id', 'email', 'first_name', 'last_name', 'phone_number', 'full_name',
            'is_staff', 'is_active', 'is_superuser', 'date_joined',
            'last_login', 'documents_count', 'role_display'
        )
        read_only_fields = ('id', 'date_joined', 'last_login')

    def get_documents_count(self, obj):
        """Nombre de documents de l'utilisateur"""
        return obj.documents.filter(is_active=True).count()

    def get_role_display(self, obj):
        """Affichage du rôle de l'utilisateur"""
        if obj.is_superuser:
            return 'Super Admin'
        elif obj.is_staff:
            return 'Administrateur'
        else:
            return 'Utilisateur'


class AdminUserCreateSerializer(serializers.ModelSerializer):
    """Serializer pour créer un utilisateur (admin)"""

    password = serializers.CharField(write_only=True, validators=[validate_password])
    password_confirm = serializers.CharField(write_only=True)

    class Meta:
        model = CustomUser
        fields = (
            'email', 'first_name', 'last_name', 'phone_number', 'password', 'password_confirm',
            'is_staff', 'is_active'
        )

    def validate(self, attrs):
        if attrs['password'] != attrs['password_confirm']:
            raise serializers.ValidationError("Les mots de passe ne correspondent pas.")
        return attrs

    def validate_email(self, value):
        if CustomUser.objects.filter(email=value).exists():
            raise serializers.ValidationError("Un utilisateur avec cet email existe déjà.")
        return value

    def create(self, validated_data):
        validated_data.pop('password_confirm')
        password = validated_data.pop('password')
        user = CustomUser.objects.create_user(password=password, **validated_data)
        return user


class AdminUserUpdateSerializer(serializers.ModelSerializer):
    """Serializer pour modifier un utilisateur (admin)"""

    class Meta:
        model = CustomUser
        fields = (
            'email', 'first_name', 'last_name', 'phone_number', 'is_staff', 'is_active'
        )

    def validate_email(self, value):
        # Vérifier que l'email n'est pas déjà utilisé par un autre utilisateur
        if self.instance and self.instance.email != value:
            if CustomUser.objects.filter(email=value).exists():
                raise serializers.ValidationError("Un utilisateur avec cet email existe déjà.")
        return value


class AdminStatsSerializer(serializers.Serializer):
    """Serializer pour les statistiques d'administration"""

    total_users = serializers.IntegerField()
    admin_users = serializers.IntegerField()
    normal_users = serializers.IntegerField()
    active_users = serializers.IntegerField()
    inactive_users = serializers.IntegerField()
    total_documents = serializers.IntegerField()
    recent_users = serializers.IntegerField()
    recent_documents = serializers.IntegerField()
