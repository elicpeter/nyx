"""py-auth-realrepo-001: Django data-migration `RunPython` callback.

Receives `(apps, schema_editor)` from the migration runtime — neither
is user-controlled.  Writing through `account.token = get_token();
account.save()` looks token-y on its surface (the assignment text
literally contains `token =`) but the function is a backend-only
schema-evolution step.  No user reach, so no token-acceptance flow
can possibly happen here.
"""

import uuid


def get_token():
    return str(uuid.uuid4())


def create_uuid(apps, schema_editor):
    User = apps.get_model("account", "User")
    for account in User.objects.all():
        account.token = get_token()
        account.save()
