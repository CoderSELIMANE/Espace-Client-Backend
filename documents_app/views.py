from rest_framework import status, generics, filters
from rest_framework.decorators import api_view, permission_classes
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework_simplejwt.tokens import RefreshToken
from django.http import HttpResponse, Http404
from django.db.models import Q, Count, Sum
from django.utils import timezone
from datetime import timedelta
from django.contrib.auth import get_user_model
from django.contrib.auth.hashers import make_password
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError
from django.db import transaction
import os
import logging

User = get_user_model()

from .models import Document
from .serializers import (
    UserRegistrationSerializer,
    UserLoginSerializer,
    UserSerializer,
    DocumentSerializer,
    DocumentUploadSerializer,
    AdminUserListSerializer,
    AdminUserCreateSerializer,
    AdminUserUpdateSerializer,
    AdminStatsSerializer
)


@api_view(['POST'])
@permission_classes([AllowAny])
def register_view(request):
    """Vue pour l'inscription des utilisateurs"""
    serializer = UserRegistrationSerializer(data=request.data)
    if serializer.is_valid():
        user = serializer.save()
        
        # Générer les tokens JWT
        refresh = RefreshToken.for_user(user)
        access_token = refresh.access_token
        
        return Response({
            'message': 'Inscription réussie',
            'user': UserSerializer(user).data,
            'tokens': {
                'refresh': str(refresh),
                'access': str(access_token),
            }
        }, status=status.HTTP_201_CREATED)
    
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


@api_view(['POST'])
@permission_classes([AllowAny])
def login_view(request):
    """Vue pour la connexion des utilisateurs"""
    serializer = UserLoginSerializer(data=request.data)
    if serializer.is_valid():
        user = serializer.validated_data['user']
        
        # Générer les tokens JWT
        refresh = RefreshToken.for_user(user)
        access_token = refresh.access_token
        
        return Response({
            'message': 'Connexion réussie',
            'user': UserSerializer(user).data,
            'tokens': {
                'refresh': str(refresh),
                'access': str(access_token),
            }
        }, status=status.HTTP_200_OK)
    
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


@api_view(['GET', 'PUT'])
@permission_classes([IsAuthenticated])
def user_profile_view(request):
    """Vue pour récupérer et mettre à jour le profil de l'utilisateur connecté"""
    if request.method == 'GET':
        serializer = UserSerializer(request.user)
        return Response(serializer.data)

    elif request.method == 'PUT':
        try:
            user = request.user
            data = request.data.copy()

            # Gestion du changement de mot de passe
            if 'new_password' in data and data['new_password']:
                current_password = data.get('current_password')
                if not current_password:
                    return Response(
                        {'current_password': ['Ce champ est requis pour changer le mot de passe.']},
                        status=status.HTTP_400_BAD_REQUEST
                    )

                # Vérifier le mot de passe actuel
                if not user.check_password(current_password):
                    return Response(
                        {'current_password': ['Mot de passe actuel incorrect.']},
                        status=status.HTTP_400_BAD_REQUEST
                    )

                # Changer le mot de passe
                user.set_password(data['new_password'])
                # Retirer les champs de mot de passe des données à sérialiser
                data.pop('current_password', None)
                data.pop('new_password', None)

            # Mettre à jour les autres champs
            serializer = UserSerializer(user, data=data, partial=True)
            if serializer.is_valid():
                serializer.save()
                return Response(serializer.data)
            else:
                return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        except Exception as e:
            return Response(
                {'error': f'Erreur lors de la mise à jour du profil: {str(e)}'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class DocumentListView(generics.ListAPIView):
    """Vue pour lister les documents de l'utilisateur connecté avec recherche et filtres"""
    serializer_class = DocumentSerializer
    permission_classes = [IsAuthenticated]
    filter_backends = [filters.SearchFilter, filters.OrderingFilter]
    search_fields = ['title', 'description']
    ordering_fields = ['uploaded_at', 'title', 'file_size']
    ordering = ['-uploaded_at']
    pagination_class = None  # Désactiver la pagination pour afficher tous les documents

    def get_queryset(self):
        # TOUS les utilisateurs voient TOUS les documents actifs
        # C'est une bibliothèque complètement partagée
        queryset = Document.objects.filter(is_active=True)

        # Filtre par type de document
        document_type = self.request.query_params.get('type', None)
        if document_type and document_type != 'all':
            queryset = queryset.filter(document_type=document_type)

        # Recherche personnalisée
        search = self.request.query_params.get('search', None)
        if search:
            queryset = queryset.filter(
                Q(title__icontains=search) |
                Q(description__icontains=search)
            )

        return queryset

    def update(self, request, *args, **kwargs):
        """Seuls les propriétaires ou les admins peuvent modifier"""
        document = self.get_object()

        # Vérifier les permissions
        if document.user != request.user and not (request.user.is_staff or request.user.is_superuser):
            return Response(
                {'error': 'Vous n\'avez pas la permission de modifier ce document'},
                status=status.HTTP_403_FORBIDDEN
            )

        return super().update(request, *args, **kwargs)

    def destroy(self, request, *args, **kwargs):
        """Seuls les propriétaires ou les admins peuvent supprimer"""
        document = self.get_object()

        # Vérifier les permissions
        if document.user != request.user and not (request.user.is_staff or request.user.is_superuser):
            return Response(
                {'error': 'Vous n\'avez pas la permission de supprimer ce document'},
                status=status.HTTP_403_FORBIDDEN
            )

        return super().destroy(request, *args, **kwargs)


class DocumentUploadView(generics.CreateAPIView):
    """Vue pour uploader un nouveau document"""
    serializer_class = DocumentUploadSerializer
    permission_classes = [IsAuthenticated]
    
    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        if serializer.is_valid():
            document = serializer.save()
            return Response({
                'message': 'Document uploadé avec succès',
                'document': DocumentSerializer(document).data
            }, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class DocumentDetailView(generics.RetrieveUpdateDestroyAPIView):
    """Vue pour récupérer, modifier ou supprimer un document"""
    serializer_class = DocumentSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        # Les administrateurs peuvent accéder à tous les documents
        if self.request.user.is_staff or self.request.user.is_superuser:
            return Document.objects.filter(is_active=True)
        # Les utilisateurs normaux ne peuvent accéder qu'à leurs propres documents
        return Document.objects.filter(user=self.request.user, is_active=True)

    def update(self, request, *args, **kwargs):
        """Seuls les propriétaires ou les admins peuvent modifier"""
        document = self.get_object()

        # Les administrateurs peuvent modifier tous les documents
        if request.user.is_staff or request.user.is_superuser:
            return super().update(request, *args, **kwargs)

        # Les utilisateurs normaux ne peuvent modifier que leurs propres documents
        if document.user != request.user:
            return Response(
                {'error': 'Vous n\'avez pas la permission de modifier ce document'},
                status=status.HTTP_403_FORBIDDEN
            )

        return super().update(request, *args, **kwargs)

    def destroy(self, request, *args, **kwargs):
        """Seuls les propriétaires ou les admins peuvent supprimer"""
        document = self.get_object()

        # Les administrateurs peuvent supprimer tous les documents
        if request.user.is_staff or request.user.is_superuser:
            return super().destroy(request, *args, **kwargs)

        # Les utilisateurs normaux ne peuvent supprimer que leurs propres documents
        if document.user != request.user:
            return Response(
                {'error': 'Vous n\'avez pas la permission de supprimer ce document'},
                status=status.HTTP_403_FORBIDDEN
            )

        return super().destroy(request, *args, **kwargs)


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def download_document_view(request, document_id):
    """Vue pour télécharger un document"""
    try:
        # Les administrateurs peuvent télécharger tous les documents
        if request.user.is_staff or request.user.is_superuser:
            document = Document.objects.get(id=document_id, is_active=True)
        else:
            # Les utilisateurs normaux ne peuvent télécharger que leurs propres documents
            document = Document.objects.get(id=document_id, user=request.user, is_active=True)
    except Document.DoesNotExist:
        raise Http404("Document non trouvé")

    if not document.file:
        raise Http404("Fichier non trouvé")

    file_path = document.file.path
    if not os.path.exists(file_path):
        raise Http404("Fichier physique non trouvé")

    # Déterminer le type MIME correct
    import mimetypes
    content_type, _ = mimetypes.guess_type(file_path)
    if not content_type:
        content_type = 'application/octet-stream'

    # Obtenir le nom de fichier original (titre du document + extension)
    file_extension = os.path.splitext(document.file.name)[1]
    safe_filename = f"{document.title}{file_extension}"

    # Nettoyer le nom de fichier pour éviter les problèmes
    import re
    import string
    # Garder seulement les caractères alphanumériques, espaces, tirets et points
    safe_chars = string.ascii_letters + string.digits + ' -.'
    safe_filename = ''.join(c for c in safe_filename if c in safe_chars)
    # Remplacer les espaces multiples par un seul tiret
    safe_filename = re.sub(r'\s+', '-', safe_filename)
    # Supprimer les tirets multiples
    safe_filename = re.sub(r'-+', '-', safe_filename)

    with open(file_path, 'rb') as file:
        response = HttpResponse(file.read(), content_type=content_type)
        response['Content-Disposition'] = f'attachment; filename="{safe_filename}"'
        response['Content-Length'] = os.path.getsize(file_path)
        response['Content-Type'] = content_type
        return response


def preview_document_view(request, document_id):
    """Vue pour prévisualiser un document (affichage inline)"""
    # Authentification via token dans l'URL ou header
    user = None

    # Essayer d'authentifier via header Authorization
    from rest_framework_simplejwt.authentication import JWTAuthentication
    try:
        jwt_auth = JWTAuthentication()
        user_auth = jwt_auth.authenticate(request)
        if user_auth:
            user = user_auth[0]
    except:
        pass

    # Si pas d'authentification via header, essayer via token dans l'URL
    if not user:
        token = request.GET.get('token')
        if token:
            try:
                from rest_framework_simplejwt.tokens import AccessToken
                access_token = AccessToken(token)
                user_id = access_token['user_id']
                from django.contrib.auth import get_user_model
                User = get_user_model()
                user = User.objects.get(id=user_id)
            except Exception as e:
                print(f"Erreur d'authentification: {e}")  # Pour debug
                return HttpResponse("Token invalide ou expiré", status=401)
        else:
            return HttpResponse("Authentification requise", status=401)

    try:
        # Maintenant tous les documents sont partagés, donc accessible à tous les utilisateurs connectés
        document = Document.objects.get(id=document_id, is_active=True)
    except Document.DoesNotExist:
        return HttpResponse("Document non trouvé", status=404)

    if not document.file:
        return HttpResponse("Fichier non trouvé", status=404)

    file_path = document.file.path
    if not os.path.exists(file_path):
        return HttpResponse("Fichier physique non trouvé", status=404)

    # Déterminer le type MIME correct
    import mimetypes
    content_type, _ = mimetypes.guess_type(file_path)
    if not content_type:
        content_type = 'application/octet-stream'

    # Obtenir le nom de fichier original
    file_extension = os.path.splitext(document.file.name)[1]
    safe_filename = f"{document.title}{file_extension}"

    # Nettoyer le nom de fichier pour éviter les problèmes
    import re
    import string
    # Garder seulement les caractères alphanumériques, espaces, tirets et points
    safe_chars = string.ascii_letters + string.digits + ' -.'
    safe_filename = ''.join(c for c in safe_filename if c in safe_chars)
    # Remplacer les espaces multiples par un seul tiret
    safe_filename = re.sub(r'\s+', '-', safe_filename)
    # Supprimer les tirets multiples
    safe_filename = re.sub(r'-+', '-', safe_filename)

    with open(file_path, 'rb') as file:
        response = HttpResponse(file.read(), content_type=content_type)
        # Pour la prévisualisation, on utilise 'inline' au lieu de 'attachment'
        response['Content-Disposition'] = f'inline; filename="{safe_filename}"'
        response['Content-Length'] = os.path.getsize(file_path)
        response['Content-Type'] = content_type

        # Headers pour permettre l'affichage dans iframe et éviter les problèmes CORS
        response['X-Frame-Options'] = 'SAMEORIGIN'
        response['Content-Security-Policy'] = "frame-ancestors 'self'  https://espace-client-frontend-seven.vercel.app/"
        response['Access-Control-Allow-Origin'] = '*'  # Permettre toutes les origines pour la preview
        response['Access-Control-Allow-Credentials'] = 'true'
        response['Access-Control-Allow-Methods'] = 'GET, HEAD, OPTIONS'
        response['Access-Control-Allow-Headers'] = 'Authorization, Content-Type'

        return response


def test_auth_view(request):
    """Vue de test pour vérifier l'authentification par token"""
    token = request.GET.get('token')
    if not token:
        return HttpResponse(f"Aucun token fourni. URL: {request.get_full_path()}", status=400)

    try:
        from rest_framework_simplejwt.tokens import AccessToken
        access_token = AccessToken(token)
        user_id = access_token['user_id']
        return HttpResponse(f"Token valide pour l'utilisateur {user_id}")
    except Exception as e:
        return HttpResponse(f"Token invalide: {str(e)}", status=401)


def test_filename_view(request, document_id):
    """Vue de test pour vérifier la génération du nom de fichier"""
    try:
        document = Document.objects.get(id=document_id, is_active=True)

        # Simuler la génération du nom de fichier
        import mimetypes

        file_path = document.file.path
        content_type, _ = mimetypes.guess_type(file_path)
        if content_type is None:
            content_type = 'application/octet-stream'

        file_extension = os.path.splitext(document.file.name)[1]
        if not file_extension:
            mime_to_ext = {
                'application/pdf': '.pdf',
                'image/jpeg': '.jpg',
                'image/png': '.png',
                'application/msword': '.doc',
                'application/vnd.openxmlformats-officedocument.wordprocessingml.document': '.docx',
            }
            file_extension = mime_to_ext.get(content_type, '.bin')

        safe_filename = f"{document.title}{file_extension}"

        info = f"""
        Document ID: {document_id}
        Titre: {document.title}
        Fichier original: {document.file.name}
        Type MIME: {content_type}
        Extension détectée: {file_extension}
        Nom final: {safe_filename}
        """

        return HttpResponse(info, content_type='text/plain')

    except Document.DoesNotExist:
        return HttpResponse("Document non trouvé", status=404)


def test_download_simple(request, document_id):
    """Vue de test simple pour le téléchargement"""
    try:
        document = Document.objects.get(id=document_id, is_active=True)
        return HttpResponse(f"Document trouvé: {document.title} - Fichier: {document.file.name}")
    except Document.DoesNotExist:
        return HttpResponse("Document non trouvé", status=404)
    except Exception as e:
        return HttpResponse(f"Erreur: {str(e)}", status=500)


def download_document_view(request, document_id):
    """Vue pour télécharger un document"""
    # Authentification via token dans l'URL ou header
    user = None

    # Essayer d'authentifier via header Authorization
    from rest_framework_simplejwt.authentication import JWTAuthentication
    try:
        jwt_auth = JWTAuthentication()
        user_auth = jwt_auth.authenticate(request)
        if user_auth:
            user = user_auth[0]
    except:
        pass

    # Si pas d'authentification via header, essayer via token dans l'URL
    if not user:
        token = request.GET.get('token')
        if token:
            try:
                from rest_framework_simplejwt.tokens import AccessToken
                access_token = AccessToken(token)
                user_id = access_token['user_id']
                from django.contrib.auth import get_user_model
                User = get_user_model()
                user = User.objects.get(id=user_id)
            except Exception as e:
                print(f"Erreur d'authentification: {e}")  # Pour debug
                return HttpResponse("Token invalide ou expiré", status=401)
        else:
            return HttpResponse("Authentification requise", status=401)

    try:
        # Tous les documents sont partagés, donc accessible à tous les utilisateurs connectés
        document = Document.objects.get(id=document_id, is_active=True)
    except Document.DoesNotExist:
        return HttpResponse("Document non trouvé", status=404)

    # Chemin du fichier
    try:
        file_path = document.file.path
        if not os.path.exists(file_path):
            return HttpResponse("Fichier non trouvé sur le serveur", status=404)
    except Exception as e:
        print(f"Erreur d'accès au fichier: {e}")
        return HttpResponse("Erreur d'accès au fichier", status=500)

    # Déterminer le type de contenu
    import mimetypes
    content_type, _ = mimetypes.guess_type(file_path)
    if content_type is None:
        content_type = 'application/octet-stream'

    # Nom de fichier sécurisé avec extension
    import urllib.parse

    # Obtenir l'extension du fichier original
    file_extension = os.path.splitext(document.file.name)[1]
    if not file_extension:
        # Si pas d'extension, deviner à partir du type MIME
        mime_to_ext = {
            'application/pdf': '.pdf',
            'application/msword': '.doc',
            'application/vnd.openxmlformats-officedocument.wordprocessingml.document': '.docx',
            'application/vnd.ms-excel': '.xls',
            'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet': '.xlsx',
            'application/vnd.ms-powerpoint': '.ppt',
            'application/vnd.openxmlformats-officedocument.presentationml.presentation': '.pptx',
            'text/plain': '.txt',
            'text/html': '.html',
            'image/jpeg': '.jpg',
            'image/png': '.png',
            'image/gif': '.gif',
            'image/bmp': '.bmp',
            'image/svg+xml': '.svg',
            'application/zip': '.zip',
            'application/x-rar-compressed': '.rar',
            'application/x-7z-compressed': '.7z'
        }

        file_extension = mime_to_ext.get(content_type, '.bin')

        # Cas spéciaux pour les images
        if content_type.startswith('image/') and file_extension == '.bin':
            file_extension = '.jpg'  # Par défaut pour les images

    # Créer le nom de fichier avec extension
    safe_filename = f"{document.title}{file_extension}"

    # Nettoyer le nom de fichier pour éviter les caractères problématiques
    import re
    import string
    # Garder seulement les caractères alphanumériques, espaces, tirets, points et underscores
    safe_chars = string.ascii_letters + string.digits + ' -._'
    safe_filename = ''.join(c for c in safe_filename if c in safe_chars)
    # Remplacer les espaces multiples par un seul tiret
    safe_filename = re.sub(r'\s+', '-', safe_filename)
    # Supprimer les tirets multiples
    safe_filename = re.sub(r'-+', '-', safe_filename)

    # Encoder pour l'URL
    safe_filename = urllib.parse.quote(safe_filename)

    # Log pour debug
    print(f"Téléchargement: {document.title} -> {safe_filename} (type: {content_type})")

    # Retourner le fichier en téléchargement
    try:
        with open(file_path, 'rb') as file:
            response = HttpResponse(file.read(), content_type=content_type)
            # Pour le téléchargement, on utilise 'attachment'
            response['Content-Disposition'] = f'attachment; filename="{safe_filename}"'
            response['Content-Length'] = os.path.getsize(file_path)
            response['Content-Type'] = content_type

            # Headers CORS pour éviter les problèmes
            response['Access-Control-Allow-Origin'] = 'http://localhost:3000'
            response['Access-Control-Allow-Credentials'] = 'true'
            response['Access-Control-Allow-Methods'] = 'GET, HEAD, OPTIONS'
            response['Access-Control-Allow-Headers'] = 'Authorization, Content-Type'

            return response
    except Exception as e:
        print(f"Erreur lors de la lecture du fichier: {e}")
        return HttpResponse("Erreur lors de la lecture du fichier", status=500)


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def user_stats_view(request):
    """Vue pour récupérer les statistiques de l'utilisateur"""
    user_documents = Document.objects.filter(user=request.user, is_active=True)

    # Statistiques générales
    total_documents = user_documents.count()
    total_size = sum(doc.file_size for doc in user_documents)

    # Documents récents (dernière semaine)
    week_ago = timezone.now() - timedelta(days=7)
    recent_uploads = user_documents.filter(uploaded_at__gte=week_ago).count()

    # Répartition par type
    types_stats = {}
    for doc_type, label in Document.DOCUMENT_TYPES:
        count = user_documents.filter(document_type=doc_type).count()
        if count > 0:
            types_stats[doc_type] = {
                'label': label,
                'count': count,
                'size': sum(doc.file_size for doc in user_documents.filter(document_type=doc_type))
            }

    return Response({
        'total_documents': total_documents,
        'total_size': total_size,
        'recent_uploads': recent_uploads,
        'types_distribution': types_stats,
        'average_file_size': total_size // total_documents if total_documents > 0 else 0,
    })


# ========================================
# VUES D'ADMINISTRATION
# ========================================

from rest_framework import viewsets, permissions
from rest_framework.decorators import action
from django.db.models import Count, Sum

logger = logging.getLogger(__name__)

class IsAdminUser(permissions.BasePermission):
    """Permission personnalisée pour les administrateurs"""

    def has_permission(self, request, view):
        return request.user.is_authenticated and request.user.is_staff

def is_admin_user(user):
    """Vérifie si l'utilisateur est un administrateur"""
    return user.is_authenticated and user.is_staff

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def admin_list_users(request):
    """Liste tous les utilisateurs - Admin seulement"""
    if not is_admin_user(request.user):
        return Response(
            {'error': 'Accès refusé. Droits administrateur requis.'},
            status=status.HTTP_403_FORBIDDEN
        )

    try:
        users = User.objects.all().order_by('-date_joined')
        users_data = []

        for user in users:
            users_data.append({
                'id': user.id,
                'email': user.email,
                'first_name': user.first_name,
                'last_name': user.last_name,
                'is_staff': user.is_staff,
                'is_active': user.is_active,
                'date_joined': user.date_joined.isoformat(),
                'last_login': user.last_login.isoformat() if user.last_login else None,
            })

        return Response({
            'users': users_data,
            'total_count': len(users_data)
        }, status=status.HTTP_200_OK)

    except Exception as e:
        logger.error(f"Erreur lors de la récupération des utilisateurs: {str(e)}")
        return Response(
            {'error': 'Erreur lors de la récupération des utilisateurs'},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )

@api_view(['DELETE'])
@permission_classes([IsAuthenticated])
def admin_delete_user(request, user_id):
    """Supprimer un utilisateur - Admin seulement"""
    if not is_admin_user(request.user):
        return Response(
            {'error': 'Accès refusé. Droits administrateur requis.'},
            status=status.HTTP_403_FORBIDDEN
        )

    try:
        user_to_delete = User.objects.get(id=user_id)

        # Empêcher la suppression de son propre compte
        if user_to_delete.id == request.user.id:
            return Response(
                {'error': 'Vous ne pouvez pas supprimer votre propre compte'},
                status=status.HTTP_400_BAD_REQUEST
            )

        # Empêcher la suppression du superuser
        if user_to_delete.is_superuser:
            return Response(
                {'error': 'Impossible de supprimer un superutilisateur'},
                status=status.HTTP_400_BAD_REQUEST
            )

        username = user_to_delete.email
        user_to_delete.delete()

        logger.info(f"Utilisateur {username} supprimé par {request.user.email}")

        return Response(
            {'message': f'Utilisateur {username} supprimé avec succès'},
            status=status.HTTP_200_OK
        )

    except User.DoesNotExist:
        return Response(
            {'error': 'Utilisateur non trouvé'},
            status=status.HTTP_404_NOT_FOUND
        )
    except Exception as e:
        logger.error(f"Erreur lors de la suppression de l'utilisateur: {str(e)}")
        return Response(
            {'error': 'Erreur lors de la suppression de l\'utilisateur'},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )

@api_view(['PATCH'])
@permission_classes([IsAuthenticated])
def admin_promote_user(request, user_id):
    """Promouvoir un utilisateur en admin - Admin seulement"""
    if not is_admin_user(request.user):
        return Response(
            {'error': 'Accès refusé. Droits administrateur requis.'},
            status=status.HTTP_403_FORBIDDEN
        )

    try:
        user_to_promote = User.objects.get(id=user_id)

        # Basculer le statut admin
        user_to_promote.is_staff = not user_to_promote.is_staff
        user_to_promote.save()

        action = "promu administrateur" if user_to_promote.is_staff else "rétrogradé utilisateur normal"

        logger.info(f"Utilisateur {user_to_promote.email} {action} par {request.user.email}")

        return Response({
            'message': f'Utilisateur {user_to_promote.email} {action} avec succès',
            'user': {
                'id': user_to_promote.id,
                'email': user_to_promote.email,
                'is_staff': user_to_promote.is_staff,
                'is_active': user_to_promote.is_active,
            }
        }, status=status.HTTP_200_OK)

    except User.DoesNotExist:
        return Response(
            {'error': 'Utilisateur non trouvé'},
            status=status.HTTP_404_NOT_FOUND
        )
    except Exception as e:
        logger.error(f"Erreur lors de la promotion de l'utilisateur: {str(e)}")
        return Response(
            {'error': 'Erreur lors de la modification des droits utilisateur'},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )

@api_view(['POST'])
@permission_classes([IsAuthenticated])
def admin_create_user(request):
    """Créer un nouvel utilisateur - Admin seulement"""
    if not is_admin_user(request.user):
        return Response(
            {'error': 'Accès refusé. Droits administrateur requis.'},
            status=status.HTTP_403_FORBIDDEN
        )

    try:
        data = request.data

        # Validation des champs requis
        required_fields = ['email', 'password']
        for field in required_fields:
            if not data.get(field):
                return Response(
                    {'error': f'Le champ {field} est requis'},
                    status=status.HTTP_400_BAD_REQUEST
                )

        # Vérifier si l'utilisateur existe déjà
        if User.objects.filter(email=data['email']).exists():
            return Response(
                {'error': 'Un utilisateur avec cet email existe déjà'},
                status=status.HTTP_400_BAD_REQUEST
            )

        # Validation du mot de passe
        try:
            validate_password(data['password'])
        except ValidationError as e:
            return Response(
                {'error': f'Mot de passe invalide: {", ".join(e.messages)}'},
                status=status.HTTP_400_BAD_REQUEST
            )

        # Créer l'utilisateur
        with transaction.atomic():
            new_user = User.objects.create_user(
                email=data['email'],
                password=data['password'],
                first_name=data.get('first_name', ''),
                last_name=data.get('last_name', ''),
                is_staff=data.get('is_staff', False),
                is_active=True
            )

        logger.info(f"Nouvel utilisateur {new_user.email} créé par {request.user.email}")

        return Response({
            'message': f'Utilisateur {new_user.email} créé avec succès',
            'user': {
                'id': new_user.id,
                'email': new_user.email,
                'first_name': new_user.first_name,
                'last_name': new_user.last_name,
                'is_staff': new_user.is_staff,
                'is_active': new_user.is_active,
                'date_joined': new_user.date_joined.isoformat(),
            }
        }, status=status.HTTP_201_CREATED)

    except Exception as e:
        logger.error(f"Erreur lors de la création de l'utilisateur: {str(e)}")
        return Response(
            {'error': 'Erreur lors de la création de l\'utilisateur'},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def admin_stats(request):
    """Statistiques pour le dashboard admin"""
    if not is_admin_user(request.user):
        return Response(
            {'error': 'Accès refusé. Droits administrateur requis.'},
            status=status.HTTP_403_FORBIDDEN
        )

    try:
        total_users = User.objects.count()
        admin_users = User.objects.filter(is_staff=True).count()
        active_users = User.objects.filter(is_active=True).count()
        inactive_users = User.objects.filter(is_active=False).count()

        return Response({
            'total_users': total_users,
            'admin_users': admin_users,
            'normal_users': total_users - admin_users,
            'active_users': active_users,
            'inactive_users': inactive_users,
        }, status=status.HTTP_200_OK)

    except Exception as e:
        logger.error(f"Erreur lors de la récupération des statistiques: {str(e)}")
        return Response(
            {'error': 'Erreur lors de la récupération des statistiques'},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )


# ========================================
# VIEWSETS D'ADMINISTRATION MODERNES
# ========================================

class AdminUserViewSet(viewsets.ModelViewSet):
    """ViewSet pour la gestion des utilisateurs par les administrateurs"""

    queryset = User.objects.all().order_by('-date_joined')
    permission_classes = [IsAdminUser]

    def get_serializer_class(self):
        if self.action == 'create':
            return AdminUserCreateSerializer
        elif self.action in ['update', 'partial_update']:
            return AdminUserUpdateSerializer
        return AdminUserListSerializer

    def get_queryset(self):
        queryset = super().get_queryset()

        # Filtrage par rôle
        role = self.request.query_params.get('role', None)
        if role == 'admin':
            queryset = queryset.filter(is_staff=True)
        elif role == 'user':
            queryset = queryset.filter(is_staff=False)

        # Filtrage par statut
        status_filter = self.request.query_params.get('status', None)
        if status_filter == 'active':
            queryset = queryset.filter(is_active=True)
        elif status_filter == 'inactive':
            queryset = queryset.filter(is_active=False)

        # Recherche
        search = self.request.query_params.get('search', None)
        if search:
            queryset = queryset.filter(
                Q(email__icontains=search) |
                Q(first_name__icontains=search) |
                Q(last_name__icontains=search)
            )

        return queryset

    def destroy(self, request, *args, **kwargs):
        """Supprimer un utilisateur avec vérifications"""
        user_to_delete = self.get_object()

        # Empêcher la suppression de son propre compte
        if user_to_delete.id == request.user.id:
            return Response(
                {'error': 'Vous ne pouvez pas supprimer votre propre compte'},
                status=status.HTTP_400_BAD_REQUEST
            )

        # Empêcher la suppression du superuser
        if user_to_delete.is_superuser:
            return Response(
                {'error': 'Impossible de supprimer un superutilisateur'},
                status=status.HTTP_400_BAD_REQUEST
            )

        username = user_to_delete.email
        response = super().destroy(request, *args, **kwargs)

        logger.info(f"Utilisateur {username} supprimé par {request.user.email}")

        return Response(
            {'message': f'Utilisateur {username} supprimé avec succès'},
            status=status.HTTP_200_OK
        )

    @action(detail=True, methods=['patch'])
    def toggle_admin(self, request, pk=None):
        """Promouvoir/rétrograder un utilisateur"""
        user_to_modify = self.get_object()

        # Basculer le statut admin
        user_to_modify.is_staff = not user_to_modify.is_staff
        user_to_modify.save()

        action_text = "promu administrateur" if user_to_modify.is_staff else "rétrogradé utilisateur normal"

        logger.info(f"Utilisateur {user_to_modify.email} {action_text} par {request.user.email}")

        return Response({
            'message': f'Utilisateur {user_to_modify.email} {action_text} avec succès',
            'user': AdminUserListSerializer(user_to_modify).data
        }, status=status.HTTP_200_OK)

    @action(detail=True, methods=['patch'])
    def toggle_active(self, request, pk=None):
        """Activer/désactiver un utilisateur"""
        user_to_modify = self.get_object()

        # Empêcher la désactivation de son propre compte
        if user_to_modify.id == request.user.id:
            return Response(
                {'error': 'Vous ne pouvez pas désactiver votre propre compte'},
                status=status.HTTP_400_BAD_REQUEST
            )

        # Basculer le statut actif
        user_to_modify.is_active = not user_to_modify.is_active
        user_to_modify.save()

        action_text = "activé" if user_to_modify.is_active else "désactivé"

        logger.info(f"Utilisateur {user_to_modify.email} {action_text} par {request.user.email}")

        return Response({
            'message': f'Utilisateur {user_to_modify.email} {action_text} avec succès',
            'user': AdminUserListSerializer(user_to_modify).data
        }, status=status.HTTP_200_OK)

    @action(detail=False, methods=['get'])
    def stats(self, request):
        """Statistiques pour le dashboard admin"""
        try:
            total_users = User.objects.count()
            admin_users = User.objects.filter(is_staff=True).count()
            active_users = User.objects.filter(is_active=True).count()
            inactive_users = User.objects.filter(is_active=False).count()

            # Statistiques des documents
            total_documents = Document.objects.filter(is_active=True).count()

            # Utilisateurs récents (dernière semaine)
            week_ago = timezone.now() - timedelta(days=7)
            recent_users = User.objects.filter(date_joined__gte=week_ago).count()
            recent_documents = Document.objects.filter(uploaded_at__gte=week_ago, is_active=True).count()

            stats_data = {
                'total_users': total_users,
                'admin_users': admin_users,
                'normal_users': total_users - admin_users,
                'active_users': active_users,
                'inactive_users': inactive_users,
                'total_documents': total_documents,
                'recent_users': recent_users,
                'recent_documents': recent_documents,
            }

            serializer = AdminStatsSerializer(stats_data)
            return Response(serializer.data, status=status.HTTP_200_OK)

        except Exception as e:
            logger.error(f"Erreur lors de la récupération des statistiques: {str(e)}")
            return Response(
                {'error': 'Erreur lors de la récupération des statistiques'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
