from django.contrib import admin
from django_github import models


@admin.register(models.GithubIntegration)
class IntegrationAdmin(admin.ModelAdmin):
    list_display = ('name', 'organisation', 'description', '_actions', 'enabled')
    search_fields = ('name', 'description')
    exclude = ('content_source',)

    def _actions(self, obj):
        return ', '.join(obj.actions)

    _actions.short_description = 'Actions'


@admin.register(models.GithubRepository)
class GithubRepositoryAdmin(admin.ModelAdmin):
    list_display = ('name', 'active', 'url', 'type', 'scan_required', 'sca', 'sast', 'sts', 'integration', 'last_seen')
    search_fields = ('name', 'url')
    list_filter = (
        'active',
        'type',
        'scan_required',
        'sca',
        'sast',
        'sts',
        ('integration', admin.RelatedOnlyFieldListFilter),
    )

    def has_add_permission(self, request):
        return False

    def has_change_permission(self, request, obj=None):
        return False


@admin.register(models.GithubUser)
class GithubUserAdmin(admin.ModelAdmin):
    list_display = ('id', 'name', 'email')
    search_fields = ('name', 'email')
    readonly_fields = ('id', 'name', 'email')

    def has_add_permission(self, request):
        return False

    def has_change_permission(self, request, obj=None):
        return False


@admin.register(models.GithubTeam)
class GithubTeamAdmin(admin.ModelAdmin):
    list_display = ('id', 'name')
    search_fields = ('name',)
    readonly_fields = ('id', 'name', 'members')

    def has_add_permission(self, request):
        return False

    def has_change_permission(self, request, obj=None):
        return False


@admin.register(models.DependencyFinding)
class DependencyFindingAdmin(admin.ModelAdmin):
    list_display = ('number', 'repository', 'state', 'dismissed_reason', 'dismissed_comment', 'url')
    search_fields = ('identifiers', 'repository', 'dismissed_reason', 'dismissed_comment')
    list_filter = ('apps', 'integration', 'repository', 'severity', 'state', 'first_seen', 'last_seen_date')

    def has_add_permission(self, request):
        return False

    def has_change_permission(self, request, obj=None):
        return False


@admin.register(models.CodeFinding)
class CodeFindingAdmin(admin.ModelAdmin):
    list_display = ('number', 'repository', 'state', 'dismissed_reason', 'dismissed_comment', 'url')
    search_fields = ('repository', 'dismissed_reason', 'dismissed_comment')
    list_filter = ('apps', 'integration', 'repository', 'severity', 'state', 'first_seen', 'last_seen_date')

    def has_add_permission(self, request):
        return False

    def has_change_permission(self, request, obj=None):
        return False


@admin.register(models.SecretFinding)
class SecretFindingAdmin(admin.ModelAdmin):
    list_display = (
        'number',
        'repository',
        'state',
        'secret',
        'resolution',
        'push_protection_bypassed',
        'push_protection_comment',
        'url',
    )
    search_fields = ('repository', 'resolution', 'push_protection_bypassed', 'push_protection_comment')
    list_filter = (
        'apps',
        'integration',
        'repository',
        'severity',
        'state',
        'push_protection_bypassed',
        'first_seen',
        'last_seen_date',
    )

    def has_add_permission(self, request):
        return False

    def has_change_permission(self, request, obj=None):
        return False
