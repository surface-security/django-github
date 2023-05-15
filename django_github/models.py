from django.db import models
from django.utils import timezone
from inventory import models as inv_models


class GithubIntegration(inv_models.Integration):
    class Action(models.TextChoices):
        users = 'Users'
        repositories = 'Repositories'
        codeowners = 'Codeowners'
        findings = 'Findings'

    app_id = models.CharField(max_length=255, blank=True)
    app_installation_id = models.CharField(max_length=255, blank=True)
    organisation = models.CharField(max_length=255)

    def __str__(self):
        return self.name

    class Meta:
        verbose_name = "Github Integration"
        verbose_name_plural = "Github Integrations"


class GithubRepository(inv_models.GitRepository):
    owners = models.ManyToManyField('django_github.GithubUser')

    def __str__(self):
        return self.name

    class Meta:
        verbose_name = 'Github Repository'
        verbose_name_plural = 'Github Repositories'


class GithubUser(models.Model):
    # username
    id = models.CharField(max_length=128, null=False, primary_key=True)
    name = models.CharField(max_length=128, null=True, editable=False)
    email = models.EmailField(max_length=254, null=True, editable=False)
    integration = models.ForeignKey(
        GithubIntegration, null=True, on_delete=models.CASCADE, related_name='+', editable=False
    )

    active = models.BooleanField(default=True, editable=False)
    first_seen = models.DateTimeField(default=timezone.now, editable=False)
    last_seen = models.DateTimeField(default=timezone.now, editable=False)

    def __str__(self):
        return self.id

    class Meta:
        verbose_name = 'Github User'
        verbose_name_plural = 'Github Users'


class GithubTeam(models.Model):
    id = models.CharField(max_length=128, null=False, primary_key=True, editable=False)
    name = models.CharField(max_length=128, null=False, editable=False)
    description = models.CharField(max_length=256, null=True, blank=True, editable=False)
    members = models.ManyToManyField(GithubUser, editable=False)
    integration = models.ForeignKey(
        GithubIntegration, null=True, on_delete=models.CASCADE, related_name='+', editable=False
    )

    active = models.BooleanField(default=True, editable=False)
    first_seen = models.DateTimeField(default=timezone.now, editable=False)
    last_seen = models.DateTimeField(default=timezone.now, editable=False)

    def __str__(self):
        return self.name

    class Meta:
        verbose_name = 'Github Team'
        verbose_name_plural = 'Github Teams'


# Github Advanced Security | Software Composition Analysis (SCA) | Dependency Scanning
class DependencyFinding(inv_models.Finding):
    # Finding number - repository
    number = models.IntegerField(editable=False)
    repository = models.ForeignKey('inventory.GitRepository', on_delete=models.CASCADE, editable=False)
    url = models.URLField(null=True, blank=True, editable=False)
    dismissed_reason = models.TextField(null=True, blank=True, editable=False)
    dismissed_comment = models.TextField(null=True, blank=True, editable=False)
    identifiers = models.JSONField(null=True, editable=False)

    class Meta:
        verbose_name = 'Github Dependency Finding'
        verbose_name_plural = 'Github Dependency Findings'


# Github Advanced Security | Static Application Security Testing (SAST) | Code Scanning
class CodeFinding(inv_models.Finding):
    # Finding number - repository
    number = models.IntegerField(editable=False)
    repository = models.ForeignKey('inventory.GitRepository', on_delete=models.CASCADE, editable=False)
    url = models.URLField(null=True, blank=True, editable=False)
    dismissed_reason = models.TextField(null=True, blank=True, editable=False)
    dismissed_comment = models.TextField(null=True, blank=True, editable=False)

    class Meta:
        verbose_name = 'Github Code Finding'
        verbose_name_plural = 'Github Code Findings'


# Github Advanced Security | Secrets Scanning (STS) | Secrets Scanning
class SecretFinding(inv_models.Finding):
    # Finding number - repository
    number = models.IntegerField(editable=False)
    repository = models.ForeignKey('inventory.GitRepository', on_delete=models.CASCADE, editable=False)
    url = models.URLField(null=True, blank=True, editable=False)
    secret_type = models.CharField(max_length=255, null=True, blank=True, editable=False)
    secret = models.TextField(null=True, blank=True, editable=False)
    resolution = models.CharField(max_length=255, null=True, blank=True, editable=False)
    push_protection_bypassed = models.BooleanField(default=False, editable=False)
    push_protection_comment = models.TextField(null=True, blank=True, editable=False)

    class Meta:
        verbose_name = 'Github Secret Finding'
        verbose_name_plural = 'Github Secret Findings'
