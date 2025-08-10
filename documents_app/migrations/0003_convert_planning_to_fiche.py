# Generated manually to convert planning documents to fiche

from django.db import migrations


def convert_planning_to_fiche(apps, schema_editor):
    """Convertir tous les documents de type 'planning' vers 'fiche'"""
    Document = apps.get_model('documents_app', 'Document')
    
    # Mettre à jour tous les documents de type 'planning' vers 'fiche'
    planning_docs = Document.objects.filter(document_type='planning')
    count = planning_docs.count()
    
    if count > 0:
        planning_docs.update(document_type='fiche')
        print(f"Converted {count} planning documents to fiche type")
    else:
        print("No planning documents found to convert")


def reverse_convert_fiche_to_planning(apps, schema_editor):
    """Fonction de retour (optionnelle) - ne fait rien car on ne peut pas savoir 
    quels documents 'fiche' étaient originalement 'planning'"""
    pass


class Migration(migrations.Migration):

    dependencies = [
        ('documents_app', '0002_remove_planning_type'),
    ]

    operations = [
        migrations.RunPython(
            convert_planning_to_fiche,
            reverse_convert_fiche_to_planning,
        ),
    ]
