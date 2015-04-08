from django.core.management.base import BaseCommand
from subprocess import call


class Command(BaseCommand):
    args = ''
    help = 'Runs build tasks to compile javascript and css'

    def handle(self, *args, **options):
        self.stdout.write('Task `dist`: compile front end resources with npm version...')

        call(['gulp', 'build'])

        self.stdout.write('SUCCESS: compiled front end resources')
