from datetime import timezone
from django.core.management.base import BaseCommand
from django.db.models import Q
from django.utils import timezone
from django_github import models as gh_models
from django_github.utils import _get_token
from inventory import models as inv_models

import base64
import requests
import logging

logger = logging.getLogger(__name__)


class Command(BaseCommand):
    help = 'Ingest Github repositories & findings'

    header, per_page = None, 100

    def handle(self, *args, **options):
        integrations = gh_models.GithubIntegration.objects.all()

        for integration in integrations:
            self._set_default_state(integration)

            if not integration.enabled:
                continue

            GITHUB_TOKEN = _get_token(integration.app_id, integration.secrets, integration.app_installation_id)
            self.headers = {"Authorization": f"token {GITHUB_TOKEN}"}

            if gh_models.GithubIntegration.Action.repositories in integration.actions:
                self._parse_repositories(integration)

    def _parse_repositories(self, integration):
        """
        GET https://api.github.com/orgs/{owner}/repos
        """
        page_num = 1

        while True:
            response = requests.get(
                f'https://api.github.com/orgs/{integration.organisation}/repos?page={page_num}&per_page={self.per_page}',
                headers=self.headers,
            )
            if response.status_code != 200:
                return False

            repos = response.json()
            if not repos:
                break

            for r in repos:
                type, active = self._get_type_and_state(r)

                repo, _ = gh_models.GithubRepository.objects.update_or_create(
                    integration=integration,
                    url=r['html_url'],
                    defaults={
                        'name': r['name'],
                        'type': type,
                        'active': active,
                    },
                )

                if gh_models.GithubIntegration.Action.findings in integration.actions:
                    self._parse_findings(repo, integration)

                if gh_models.GithubIntegration.Action.codeowners in integration.actions:
                    self._parse_codeowners(repo, integration)

            page_num += 1

        return True

    def _parse_findings(self, repo, integration):
        sca = self._get_dependency_alerts(repo, integration)
        if sca:
            repo.sca = sca

        sast = self._get_code_alerts(repo, integration)
        if sast:
            repo.sast = sast

        sts = self._get_secret_alerts(repo, integration)
        if sts:
            repo.sts = sts

        repo.save()

    def _get_dependency_alerts(self, repo, integration):
        # https://docs.github.com/en/rest/dependabot/alerts?apiVersion=2022-11-28#list-dependabot-alerts-for-a-repository
        """
        GET https://api.github.com/repos/{owner}/{repo}/dependabot/alerts
        """
        page_num = 1

        while True:
            response = requests.get(
                f'https://api.github.com/repos/{integration.organisation}/{repo.name}/dependabot/alerts?page={page_num}&per_page={self.per_page}',
                headers=self.headers,
            )

            if response.status_code != 200:
                return False

            applications = inv_models.Application.objects.filter(git_repos=repo)
            if not applications:
                applications = inv_models.Application.objects.filter(tla='unknown')

            findings = response.json()
            if not findings:
                break

            for f in findings:
                resolution = self._get_resolution(f['state'].lower(), f['dismissed_reason'])
                finding, _ = gh_models.DependencyFinding.objects.update_or_create(
                    number=f.get('number'),
                    repository=repo,
                    defaults={
                        'integration': integration,
                        'summary': f['security_advisory']['description'],
                        'identifiers': [identifier['value'] for identifier in f['security_advisory']['identifiers']],
                        'state': resolution,
                        'url': f['html_url'],
                        'dismissed_reason': f.get('dismissed_reason'),
                        'dismissed_comment': f.get('dismissed_comment'),
                        'severity': self._get_severity(f['security_advisory']['severity']),
                        'last_seen_date': timezone.now(),
                    },
                )

                finding.apps.clear()
                finding.apps.add(*applications)
                finding.save()

            page_num += 1

        return True

    def _get_severity(self, severity):
        return getattr(inv_models.Finding.Severity, severity.upper(), inv_models.Finding.Severity.INFORMATIVE)

    def _get_code_alerts(self, repo, integration):
        # https://docs.github.com/en/rest/reference/code-scanning#list-code-scanning-alerts-for-a-repository
        """
        GET https://api.github.com/repos/{owner}/{repo}/code-scanning/alerts
        """
        page_num = 1

        while True:
            response = requests.get(
                f'https://api.github.com/repos/{integration.organisation}/{repo.name}/code-scanning/alerts?page={page_num}&per_page={self.per_page}',
                headers=self.headers,
            )

            if response.status_code != 200:
                return False

            applications = inv_models.Application.objects.filter(git_repos=repo)
            if not applications:
                applications = inv_models.Application.objects.filter(tla='unknown')

            findings = response.json()
            if not findings:
                break

            for f in findings:
                resolution = self._get_resolution(f['state'].lower(), f['dismissed_reason'])
                finding, _ = gh_models.CodeFinding.objects.update_or_create(
                    number=f.get('number'),
                    repository=repo,
                    defaults={
                        'integration': integration,
                        'summary': f"{f['rule']['description']}. {f['most_recent_instance']['message']['text']} \
                                        \n{f['most_recent_instance']['location']['path']}:{f['most_recent_instance']['location']['start_line']}-{f['most_recent_instance']['location']['end_line']}",
                        'state': resolution,
                        'url': f.get('html_url'),
                        'dismissed_reason': f.get('dismissed_reason'),
                        'dismissed_comment': f.get('dismissed_comment'),
                        'severity': self._get_severity(f['rule'].get('security_severity_level', 'informative')),
                        'last_seen_date': timezone.now(),
                    },
                )
                finding.apps.clear()
                finding.apps.add(*applications)
                finding.save()

            page_num += 1

        return True

    def _get_secret_alerts(self, repo, integration):
        # https://docs.github.com/en/rest/reference/code-scanning#list-code-scanning-alerts-for-a-repository
        # /repos/{owner}/{repo}/secret-scanning/alerts
        """
        GET https://api.github.com/repos/{owner}/{repo}/code-scanning/alerts
        """
        page_num = 1

        while True:
            response = requests.get(
                f'https://api.github.com/repos/{integration.organisation}/{repo.name}/secret-scanning/alerts?page={page_num}&per_page={self.per_page}',
                headers=self.headers,
            )

            if response.status_code != 200:
                return False

            applications = inv_models.Application.objects.filter(git_repos=repo)
            if not applications:
                applications = inv_models.Application.objects.filter(tla='unknown')

            findings = response.json()
            if not findings:
                break

            for f in findings:
                resolution = self._get_resolution(f['state'], f['resolution'])
                finding, _ = gh_models.SecretFinding.objects.update_or_create(
                    number=f['number'],
                    repository=repo,
                    defaults={
                        'integration': integration,
                        'summary': f"{f['secret_type']} secret found",
                        'state': resolution,
                        'url': f['html_url'],
                        'secret_type': f['secret_type'],
                        'secret': f['secret'],
                        'resolution': f['resolution'],
                        'push_protection_bypassed': f['push_protection_bypassed'],
                        'push_protection_comment': f['resolution_comment'],
                        'severity': inv_models.Finding.Severity.HIGH,
                        'last_seen_date': timezone.now(),
                    },
                )
                finding.apps.clear()
                finding.apps.add(*applications)
                finding.save()

            page_num += 1

        return True

    def _parse_codeowners(self, repo, integration):
        """
        GET https://api.github.com/repos/{owner}/{repo}/contents/CODEOWNERS
        GET https://api.github.com/repos/{owner}/{repo}/contents/.github/CODEOWNERS
        """
        urls = [
            f'https://api.github.com/repos/{integration.organisation}/{repo.name}/contents/CODEOWNERS',
            f'https://api.github.com/repos/{integration.organisation}/{repo.name}/contents/.github/CODEOWNERS',
        ]

        for url in urls:
            response = requests.get(url, headers=self.headers)
            codeowners = response.json()

            if not codeowners.get('name'):
                continue

            content = codeowners.get('content')
            if content:
                repo.owners.clear()
                owners = base64.b64decode(content).decode("utf-8").split('\n')
                for o in owners:
                    for ow in o.split():
                        if '@' in ow:
                            owner = gh_models.GithubUser.objects.filter(Q(id=ow[1:]) | Q(email=ow)).first()
                            if owner:
                                repo.owners.add(owner)

                            team = gh_models.GithubTeam.objects.filter(id=ow.lower()).first()
                            if team:
                                repo.owners.add(*team.members.all())

                break

            else:
                repo.owners.clear()

    def _get_type_and_state(self, repo):
        types = {
            'public': (inv_models.GitRepository.RepositoryType.public, True),
            'internal': (inv_models.GitRepository.RepositoryType.internal, True),
            'private': (inv_models.GitRepository.RepositoryType.private, True),
            'forked': (inv_models.GitRepository.RepositoryType.forked, True),
            'mirrored': (inv_models.GitRepository.RepositoryType.mirrored, True),
            'archived': (inv_models.GitRepository.RepositoryType.archived, False),
        }

        type_key = 'public'
        if repo['archived']:
            type_key = 'archived'
        elif repo['fork']:
            type_key = 'forked'
        elif repo['private']:
            type_key = 'private'

        return types.get(type_key)[0], types.get(type_key)[1]

    def _set_default_state(self, integration):
        if gh_models.GithubIntegration.Action.repositories in integration.actions:
            gh_models.GithubRepository.objects.filter(integration=integration).update(active=False)
        else:
            gh_models.GithubRepository.objects.filter(integration=integration).delete()

        if gh_models.GithubIntegration.Action.findings in integration.actions:
            inv_models.Finding.objects.filter(integration=integration).update(state=inv_models.Finding.State.CLOSED)
        else:
            inv_models.Finding.objects.filter(integration=integration).delete()

    def _get_resolution(self, state, reason):
        resolutions = {
            'open': {'default': inv_models.Finding.State.NEW},
            'fixed': {
                'default': inv_models.Finding.State.RESOLVED,
                'false positive': inv_models.Finding.State.CLOSED,
                'won\'t fix': inv_models.Finding.State.OPEN,
                'used in tests': inv_models.Finding.State.CLOSED,
            },
            'closed': {'default': inv_models.Finding.State.CLOSED},
            'dismissed': {
                'default': inv_models.Finding.State.CLOSED,
                # Code Finding
                'false positive': inv_models.Finding.State.CLOSED,
                'won\'t fix': inv_models.Finding.State.OPEN,
                'used in tests': inv_models.Finding.State.CLOSED,
                # Dependency Finding
                'fix_started': inv_models.Finding.State.OPEN,
                'inaccurate': inv_models.Finding.State.CLOSED,
                'not_used': inv_models.Finding.State.CLOSED,
                'no_bandwidth': inv_models.Finding.State.OPEN,
                'tolerable_risk': inv_models.Finding.State.CLOSED,
            },
            'resolved': {
                'default': inv_models.Finding.State.RESOLVED,
                # Secret Finding
                'false_positive': inv_models.Finding.State.CLOSED,
                'wont_fix': inv_models.Finding.State.OPEN,
                'revoked': inv_models.Finding.State.RESOLVED,
                'used_in_tests': inv_models.Finding.State.CLOSED,
                'pattern_edited': inv_models.Finding.State.CLOSED,
            },
        }

        if not reason:
            reason = 'default'

        return resolutions.get(state).get(reason)
