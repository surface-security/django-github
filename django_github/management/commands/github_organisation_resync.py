from django.core.management.base import BaseCommand
from django_github import models as gh_models
from django_github.utils import _get_token
import requests
import logging

logger = logging.getLogger(__name__)


class Command(BaseCommand):
    help = 'Ingest Github organisation information, users and teams'

    headers = None

    def handle(self, *args, **options):
        integrations = gh_models.GithubIntegration.objects.all()

        for integration in integrations:
            self._set_default_state(integration)

            if not integration.enabled:
                continue

            GITHUB_TOKEN = _get_token(integration.app_id, integration.secrets, integration.app_installation_id)
            self.headers = {"Authorization": f"token {GITHUB_TOKEN}"}

            if gh_models.GithubIntegration.Action.users in integration.actions:
                self._parse_users(integration)
                self._parse_teams(integration)

    def _parse_users(self, integration):
        query = f"""
        query {{
            organization(login: "{integration.organisation}") {{
                membersWithRole(first: 100) {{
                    edges {{
                        node {{
                            login
                            name
                            organizationVerifiedDomainEmails(login: "{integration.organisation}")
                        }}
                    }}
                }}
            }}
        }}
        """
        variables = {'organisation': integration.organisation}

        response = requests.post(
            'https://api.github.com/graphql', json={'query': query, 'variables': variables}, headers=self.headers
        )

        if response.status_code == 200:
            users = response.json()['data']['organization']['membersWithRole']['edges']
            for u in users:
                email = None
                emails = u.get('node').get('organizationVerifiedDomainEmails')
                if emails:
                    email = emails[0]

                gh_models.GithubUser.objects.update_or_create(
                    id=u.get('node').get('login'),
                    integration=integration,
                    defaults={'email': email or '', 'name': u.get('node').get('name') or '', 'active': True},
                )
        else:
            raise Exception("Query failed to run by returning code of {}. {}".format(response.status_code, query))

    def _parse_teams(self, integration):
        """
        GET https://api.github.com/orgs/{organisation}/teams
        """
        response = requests.get(f'https://api.github.com/orgs/{integration.organisation}/teams', headers=self.headers)

        if response.status_code != 200:
            return False

        teams = response.json()

        for t in teams:
            team, _ = gh_models.GithubTeam.objects.update_or_create(
                id=f'@{integration.organisation}/{t.get("slug")}',
                integration=integration,
                defaults={'name': t.get('name'), 'description': t.get('description'), 'active': True},
            )
            team.members.clear()

            response = requests.get(f'{t.get("members_url").split("{")[0]}', headers=self.headers)
            if response.status_code != 200:
                continue

            members = response.json()
            for m in members:
                member = gh_models.GithubUser.objects.filter(id=m.get('login')).first()
                if member:
                    team.members.add(member)

            team.save()

    def _set_default_state(self, integration):
        if gh_models.GithubIntegration.Action.users in integration.actions:
            gh_models.GithubUser.objects.filter(integration=integration).update(active=False)
            gh_models.GithubTeam.objects.filter(integration=integration).update(active=False)
        else:
            gh_models.GithubUser.objects.filter(integration=integration).delete()
            gh_models.GithubTeam.objects.filter(integration=integration).delete()
