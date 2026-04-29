"""py-auth-realrepo-004: vulnerable Django invitation-acceptance view.

This is the genuine token-acceptance shape: a request handler that
looks up an invitation by an attacker-supplied token, then writes
through token-bound state (`invitation.user.email`) without
validating the token's expiry or recipient identity.  The boolean
`||` fallback into request-supplied data (`new_email or
invitation.user.email`) is the override pattern.
"""

from django.http import HttpResponse


def accept_invitation_view(request, token):
    new_email = request.POST.get("email", "")
    invitation = invitation_lookup(token)
    invitation.user.email = new_email or invitation.user.email
    invitation.user.save()
    return HttpResponse("ok")


def invitation_lookup(token):
    return Invitation.objects.get(token=token)
