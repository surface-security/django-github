# Django Github

Ingest Github organisation and repositories data.

## Integration
The integration utilises Github App to authenticate against Github and extends the `inventory.Integration` model with Github specific fields such as `app_id`, `app_installation_id` and `organisation`. 

## Actions
The following Integration actions are available in this application:
- `Users` - Ingests organisation users and teams;
- `Repositories` - Ingests organisation repositories;
- `Codeowners` - Extracts repository owners managed in [CODEOWNERS](https://docs.github.com/en/repositories/managing-your-repositorys-settings-and-features/customizing-your-repository/about-code-owners) file;
- `Findings` - Ingests Github Advance Security vulnerabilities.

## Commands
> ./manage.py github_organisation_resync
> ./manage.py github_repositories_resync

## Usage
Add `django_github` to `INSTALLED_APPS` in your `settings.py`.

To adjust the django application dependencies add the following in settings and modify per project's needs:
```
DJANGO_GITHUB_MIGRATIONS_DEPENDENCIES = {
    '0001_initial': [
        ('inventory', '0001_initial'),
    ]
}
```

The default migration dependency is:
```
('inventory', '0001_initial'),
```
