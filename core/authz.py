"""Role-based access control for the operator dashboard: employees may
only reach the Playground; managers reach every dashboard page and see
data scoped to their own team (Section 10/9.3 aggregations, all keyed on
Trace.user_id == request.user.username). A Django superuser (created via
`createsuperuser`, per README step 6) has no UserProfile at all and is
treated as an unscoped manager, preserving the admin account's existing
ability to reach every page and see every team's data."""

from functools import wraps

from django.http import HttpResponseForbidden
from django.contrib.auth.decorators import login_required

from .models import UserProfile


def get_profile(user):
    """None for an anonymous user or one with no UserProfile row (e.g. a
    superuser created via createsuperuser) — never raises."""
    if not user.is_authenticated:
        return None
    return getattr(user, "profile", None)


def is_manager(user):
    if user.is_superuser:
        return True
    profile = get_profile(user)
    return profile is not None and profile.role == UserProfile.ROLE_MANAGER


def team_user_ids(user):
    """The list of Trace.user_id values (usernames) a manager's team-scoped
    dashboard views should be restricted to: themselves + their direct
    reports. Returns None for a superuser (or any user with no profile),
    meaning "no restriction" — dashboard.py's aggregation functions treat
    user_ids=None as unscoped, matching this account's pre-auth, sees-
    everything behaviour."""
    if user.is_superuser:
        return None
    profile = get_profile(user)
    if profile is None:
        return None
    ids = [user.username]
    ids += list(
        UserProfile.objects.filter(manager=profile).values_list("user__username", flat=True)
    )
    return ids


def manager_required(view_func):
    """Gates a dashboard view to authenticated managers (or a superuser)
    only; employees get a plain 403 rather than a redirect, since there is
    nowhere else on this site for them to be sent that they can use."""
    @wraps(view_func)
    @login_required
    def wrapper(request, *args, **kwargs):
        if not is_manager(request.user):
            return HttpResponseForbidden("This page is available to managers only.")
        return view_func(request, *args, **kwargs)
    return wrapper
