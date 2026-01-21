# Generated migration for SigningHistory and Revocation features

from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
        ('usercerts', '0001_initial'),
    ]

    operations = [
        # Add new fields to UserCert
        migrations.AddField(
            model_name='usercert',
            name='serial_number',
            field=models.CharField(blank=True, db_index=True, max_length=64),
        ),
        migrations.AddField(
            model_name='usercert',
            name='expires_at',
            field=models.DateTimeField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name='usercert',
            name='revoked_at',
            field=models.DateTimeField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name='usercert',
            name='revocation_reason',
            field=models.CharField(blank=True, choices=[('unspecified', 'Unspecified'), ('key_compromise', 'Key Compromise'), ('ca_compromise', 'CA Compromise'), ('affiliation_changed', 'Affiliation Changed'), ('superseded', 'Superseded'), ('cessation_of_operation', 'Cessation of Operation'), ('certificate_hold', 'Certificate Hold'), ('privilege_withdrawn', 'Privilege Withdrawn')], max_length=32),
        ),
        migrations.AddField(
            model_name='usercert',
            name='revoked_by',
            field=models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='revoked_certs', to=settings.AUTH_USER_MODEL),
        ),
        
        # Add index on user + active for UserCert
        migrations.AddIndex(
            model_name='usercert',
            index=models.Index(fields=['user', 'active'], name='usercerts_u_user_id_7b8c12_idx'),
        ),
        migrations.AddIndex(
            model_name='usercert',
            index=models.Index(fields=['serial_number'], name='usercerts_u_serial__abc123_idx'),
        ),
        
        # Create SigningHistory model
        migrations.CreateModel(
            name='SigningHistory',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('document_name', models.CharField(max_length=512)),
                ('document_hash', models.CharField(db_index=True, max_length=64)),
                ('document_size', models.BigIntegerField(default=0)),
                ('signed_at', models.DateTimeField(auto_now_add=True, db_index=True)),
                ('reason', models.CharField(blank=True, max_length=512)),
                ('location', models.CharField(blank=True, max_length=256)),
                ('status', models.CharField(choices=[('valid', 'Valid'), ('revoked', 'Revoked'), ('expired', 'Expired'), ('invalid', 'Invalid')], db_index=True, default='valid', max_length=16)),
                ('ip_address', models.GenericIPAddressField(blank=True, null=True)),
                ('user_agent', models.CharField(blank=True, max_length=512)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
                ('revoked_at', models.DateTimeField(blank=True, null=True)),
                ('revocation_reason', models.CharField(blank=True, max_length=256)),
                ('certificate', models.ForeignKey(null=True, on_delete=django.db.models.deletion.PROTECT, related_name='signing_history', to='usercerts.usercert')),
                ('revoked_by', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='revoked_signatures', to=settings.AUTH_USER_MODEL)),
                ('user', models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, related_name='signing_history', to=settings.AUTH_USER_MODEL)),
            ],
            options={
                'verbose_name_plural': 'Signing histories',
                'ordering': ['-signed_at'],
            },
        ),
        migrations.AddIndex(
            model_name='signinghistory',
            index=models.Index(fields=['user', 'signed_at'], name='usercerts_s_user_id_def456_idx'),
        ),
        migrations.AddIndex(
            model_name='signinghistory',
            index=models.Index(fields=['document_hash'], name='usercerts_s_documen_ghi789_idx'),
        ),
        migrations.AddIndex(
            model_name='signinghistory',
            index=models.Index(fields=['status'], name='usercerts_s_status_jkl012_idx'),
        ),
        
        # Create CertificateRevocationLog model
        migrations.CreateModel(
            name='CertificateRevocationLog',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('revoked_at', models.DateTimeField(auto_now_add=True)),
                ('reason', models.CharField(max_length=32)),
                ('notes', models.TextField(blank=True)),
                ('certificate', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='revocation_logs', to='usercerts.usercert')),
                ('revoked_by', models.ForeignKey(null=True, on_delete=django.db.models.deletion.SET_NULL, to=settings.AUTH_USER_MODEL)),
            ],
            options={
                'ordering': ['-revoked_at'],
            },
        ),
    ]
