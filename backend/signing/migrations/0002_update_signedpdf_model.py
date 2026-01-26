# Generated migration for updated SignedPDF model

from django.db import migrations, models
import django.db.models.deletion
import uuid


class Migration(migrations.Migration):

    dependencies = [
        ('signing', '0001_initial'),
    ]

    operations = [
        # Drop old model
        migrations.DeleteModel(
            name='SignedPDF',
        ),
        # Create new model
        migrations.CreateModel(
            name='SignedPDF',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('pdf_id', models.CharField(default=uuid.uuid4, max_length=36, unique=True)),
                ('filename', models.CharField(max_length=255)),
                ('signed_at', models.DateTimeField(auto_now_add=True)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('is_cached', models.BooleanField(default=True)),
                ('user', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='signed_pdfs_cache', to='auth.user')),
            ],
            options={
                'ordering': ['-signed_at'],
            },
        ),
        migrations.AddIndex(
            model_name='signedpdf',
            index=models.Index(fields=['user', '-signed_at'], name='signing_sig_user_id_signed_idx'),
        ),
        migrations.AddIndex(
            model_name='signedpdf',
            index=models.Index(fields=['pdf_id'], name='signing_sig_pdf_id_idx'),
        ),
        migrations.AddIndex(
            model_name='signedpdf',
            index=models.Index(fields=['user', 'is_cached'], name='signing_sig_user_id_cached_idx'),
        ),
    ]
