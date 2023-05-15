from django.db import models
from django.contrib.contenttypes import models as ct_models
from django.utils import timezone
from fernet_fields import EncryptedTextField


class Person(models.Model):
    name = models.CharField(max_length=128)


class Integration(models.Model):
    content_source = models.ForeignKey(ct_models.ContentType, on_delete=models.CASCADE)

    name = models.CharField(max_length=255, null=False, blank=False)
    description = models.TextField(null=True, blank=True)
    actions = models.JSONField(null=False, blank=False)
    secrets = EncryptedTextField(null=True, blank=False)
    enabled = models.BooleanField(default=True)

    def __init__(self, *args, **kwargs):
        if 'content_source' not in kwargs:
            kwargs['content_source'] = self.content_type()
        super().__init__(*args, **kwargs)

    @classmethod
    def content_type(cls):
        return ct_models.ContentType.objects.get_for_model(cls)

    @property
    def cached_content_source(self):
        if self.content_source_id is not None and not Integration.content_source.is_cached(self):
            self.content_source = ct_models.ContentType.objects.get_for_id(self.content_source_id)
        return self.content_source

    def __str__(self):
        return f'{self.pk} [{self.cached_content_source.app_label}] - {self.name}'


class Application(models.Model):
    tla = models.CharField(max_length=128, blank=True, null=True, db_index=True)  # three/ten letter acronym
    managed_by = models.ForeignKey('Person', blank=True, null=True, on_delete=models.SET_NULL, related_name='+')
    owned_by = models.ForeignKey('Person', blank=True, null=True, on_delete=models.SET_NULL, related_name='+')
    director = models.ForeignKey('Person', blank=True, null=True, on_delete=models.SET_NULL, related_name='+')
    director_direct = models.ForeignKey('Person', blank=True, null=True, on_delete=models.SET_NULL, related_name='+')
    dev_lead = models.ForeignKey('Person', blank=True, null=True, on_delete=models.SET_NULL, related_name='+')
    git_repos = models.ManyToManyField('GitRepository')


class GitRepository(models.Model):
    class RepositoryType(models.TextChoices):
        public = 'Public'
        private = 'Private'
        internal = 'Internal'
        forked = 'Forked'
        archived = 'Archived'
        mirrored = 'Mirrors'

    integration = models.ForeignKey('inventory.Integration', null=True, on_delete=models.CASCADE)
    name = models.CharField(max_length=255)
    url = models.URLField(max_length=255)
    type = models.CharField(max_length=64, choices=RepositoryType.choices, default='Public')
    scan_required = models.BooleanField(default=False, verbose_name='Scan required')
    scan_priority = models.BooleanField(default=False, verbose_name='Scan priority')
    # Software Composition Analysis
    sca = models.BooleanField(default=False, verbose_name='Dependency scanning')
    # Static Application Security Testing
    sast = models.BooleanField(default=False, verbose_name='Static scanning')
    # Secrets Scanning
    sts = models.BooleanField(default=False, verbose_name='Secrets scanning')

    active = models.BooleanField(default=True)
    last_seen = models.DateTimeField(default=timezone.now, editable=False)

    class Meta:
        verbose_name = 'Git Repository'
        verbose_name_plural = 'Git Repositories'

    def __str__(self):
        return self.name


class FindingInheritanceQS(models.QuerySet):
    def get_children(self) -> list:
        return [
            getattr(m, m.content_source.model)
            for m in self.prefetch_related("content_source__model__finding_ptr").select_related('content_source')
        ]


class Finding(models.Model):
    class Severity(models.IntegerChoices):
        INFORMATIVE = 1
        LOW = 2
        MEDIUM = 3
        HIGH = 4
        CRITICAL = 5

    class State(models.IntegerChoices):
        """
        States represent a point in the workflow.
        States are not Status.
        Do not add a state if the transitions for that state are the same as an existing one.
        """

        # to be reviewed by Security Testing: NEW -> OPEN/CLOSED
        NEW = 1
        # viewed by the teams, included in score: OPEN -> CLOSED
        OPEN = 2
        # no score, nothing to do. Final state.
        CLOSED = 3
        # resolved/mitigated, can be re-open: RESOLVED -> NEW/OPEN
        RESOLVED = 4

    integration = models.ForeignKey('inventory.Integration', null=True, on_delete=models.CASCADE)
    content_source = models.ForeignKey(ct_models.ContentType, on_delete=models.CASCADE)

    title = models.TextField(blank=True)
    summary = models.TextField(null=True, blank=True)
    severity = models.IntegerField(null=True, blank=True, choices=Severity.choices, db_index=True)
    state = models.IntegerField(choices=State.choices, default=State.NEW, db_index=True)

    first_seen = models.DateTimeField(auto_now_add=True)
    last_seen_date = models.DateTimeField(blank=True, null=True)

    application = models.ForeignKey(
        'inventory.Application', blank=True, null=True, on_delete=models.SET_NULL, verbose_name="Application"
    )
    apps = models.ManyToManyField('inventory.Application', related_name='+')

    related_to = models.ManyToManyField('self', blank=True, help_text='Other findings related to this one')

    objects = FindingInheritanceQS.as_manager()

    def __init__(self, *args, **kwargs):
        if 'content_source' not in kwargs:
            kwargs['content_source'] = self.content_type()
        super().__init__(*args, **kwargs)

    @classmethod
    def content_type(cls):
        return ct_models.ContentType.objects.get_for_model(cls)

    @property
    def cached_content_source(self):
        if self.content_source_id is not None and not Finding.content_source.is_cached(self):
            self.content_source = ct_models.ContentType.objects.get_for_id(self.content_source_id)
        return self.content_source

    def __str__(self):
        return f'{self.pk} [{self.cached_content_source.app_label}] - {self.title}'
