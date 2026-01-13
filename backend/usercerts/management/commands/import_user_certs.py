from django.core.management.base import BaseCommand
from django.conf import settings
from django.contrib.auth import get_user_model
from usercerts.models import UserCert
import os


class Command(BaseCommand):
    help = 'Import existing encrypted PKCS#12 files under users/ into usercerts.UserCert'

    def add_arguments(self, parser):
        parser.add_argument('--dry-run', action='store_true', help='Show what would be imported without writing DB')

    def handle(self, *args, **options):
        base = getattr(settings, 'BASE_DIR', os.getcwd())
        users_dir = os.path.join(base, 'users')
        User = get_user_model()
        created = 0
        skipped = 0
        missing_user = 0
        if not os.path.isdir(users_dir):
            self.stdout.write(self.style.ERROR(f'Users directory not found: {users_dir}'))
            return

        for name in os.listdir(users_dir):
            user_path = os.path.join(users_dir, name)
            if not os.path.isdir(user_path):
                continue
            p12_enc = os.path.join(user_path, 'user.p12.enc')
            pass_enc = os.path.join(user_path, 'p12.pass.enc')
            if not (os.path.exists(p12_enc) and os.path.exists(pass_enc)):
                skipped += 1
                continue
            try:
                user = User.objects.get(username=name)
            except User.DoesNotExist:
                missing_user += 1
                self.stdout.write(self.style.WARNING(f'No User record for directory: {name}'))
                continue

            try:
                rel_p12 = os.path.relpath(p12_enc, base)
            except Exception:
                rel_p12 = p12_enc
            try:
                rel_pass = os.path.relpath(pass_enc, base)
            except Exception:
                rel_pass = pass_enc

            exists = UserCert.objects.filter(user=user, p12_enc_path=rel_p12).exists()
            if exists:
                skipped += 1
                continue

            if options.get('dry_run'):
                self.stdout.write(self.style.SUCCESS(f'[DRY] Would import for user {name}: {rel_p12}'))
                created += 1
                continue

            UserCert.objects.create(
                user=user,
                common_name=name,
                p12_enc_path=rel_p12,
                p12_pass_enc_path=rel_pass,
                active=True,
            )
            created += 1

        self.stdout.write(self.style.SUCCESS(f'Imported: {created}, skipped: {skipped}, missing_user_dirs: {missing_user}'))
