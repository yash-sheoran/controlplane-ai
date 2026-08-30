"""Registration/login/logout for the role-based access control described
in core/authz.py. Deliberately follows this project's existing dashboard
view style (manual request.POST parsing + manual validation + re-render
with an `error`/`errors` context) rather than introducing Django's forms
framework, since no other view in this codebase uses it."""

from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.models import User
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError
from django.db import transaction
from django.shortcuts import redirect, render
from django.utils.http import url_has_allowed_host_and_scheme
from django.views.decorators.http import require_http_methods

from .models import UserProfile

# auth.User.username is VARCHAR(150) and username is always set equal to
# email (see register() below) — bounding email length here up front means
# an overlong email fails as an ordinary form error instead of a MySQL
# DataError bubbling up as an unhandled 500 (which, under DEBUG=True,
# would render Django's technical error page with this view's local
# variables — including the plaintext password — in the traceback).
MAX_EMAIL_LENGTH = 150


def _post_login_redirect(request, user):
    next_url = request.POST.get("next") or request.GET.get("next")
    if next_url and url_has_allowed_host_and_scheme(
        next_url, allowed_hosts={request.get_host()}, require_https=request.is_secure()
    ):
        return redirect(next_url)
    if user.is_superuser or (
        getattr(user, "profile", None) and user.profile.role == UserProfile.ROLE_MANAGER
    ):
        return redirect("dashboard-home")
    return redirect("playground")


@require_http_methods(["GET", "POST"])
def register(request):
    if request.user.is_authenticated:
        return _post_login_redirect(request, request.user)

    context = {
        "roles": UserProfile.ROLE_CHOICES,
        "form_values": {"name": "", "email": "", "role": "", "manager_email": ""},
        "errors": [],
    }

    if request.method == "POST":
        name = (request.POST.get("name") or "").strip()
        email = (request.POST.get("email") or "").strip().lower()
        role = request.POST.get("role") or ""
        manager_email = (request.POST.get("manager_email") or "").strip().lower()
        password = request.POST.get("password") or ""
        confirm_password = request.POST.get("confirm_password") or ""

        context["form_values"] = {
            "name": name, "email": email, "role": role, "manager_email": manager_email,
        }

        errors = []
        if not name:
            errors.append("Name is required.")
        if not email:
            errors.append("Email is required.")
        elif len(email) > MAX_EMAIL_LENGTH:
            errors.append(f"Email must be {MAX_EMAIL_LENGTH} characters or fewer.")
        if role not in (UserProfile.ROLE_EMPLOYEE, UserProfile.ROLE_MANAGER):
            errors.append("Choose a role.")
        if not password:
            errors.append("Password is required.")
        elif password != confirm_password:
            errors.append("Password and confirmation do not match.")
        else:
            try:
                # A transient, unsaved User carrying the submitted
                # username/email/first_name so UserAttributeSimilarityValidator
                # (AUTH_PASSWORD_VALIDATORS) can actually compare the password
                # against them — without user=, that validator is a silent
                # no-op and a password identical to the registrant's own
                # email would pass.
                validate_password(
                    password, user=User(username=email, email=email, first_name=name[:150]),
                )
            except ValidationError as exc:
                errors.extend(exc.messages)

        if email and len(email) <= MAX_EMAIL_LENGTH and User.objects.filter(email__iexact=email).exists():
            errors.append("An account with this email already exists.")

        manager_profile = None
        if role == UserProfile.ROLE_EMPLOYEE:
            if not manager_email:
                errors.append("Employees must provide their manager's email.")
            else:
                manager_user = User.objects.filter(email__iexact=manager_email).first()
                manager_profile = getattr(manager_user, "profile", None) if manager_user else None
                if manager_profile is None or manager_profile.role != UserProfile.ROLE_MANAGER:
                    errors.append("No manager account was found with that email.")

        if not errors:
            try:
                with transaction.atomic():
                    user = User.objects.create_user(
                        username=email, email=email, password=password, first_name=name[:150],
                    )
                    UserProfile.objects.create(
                        user=user, role=role,
                        manager=manager_profile if role == UserProfile.ROLE_EMPLOYEE else None,
                    )
            except Exception:
                # Never let an unexpected DB error surface as Django's own
                # unhandled-exception page: under DEBUG=True that page's
                # local-variable dump would include this function's
                # plaintext password/confirm_password.
                errors.append("Registration could not be completed. Please try again.")
                context["errors"] = errors
                return render(request, "core/register.html", context)

            login(request, user)
            return _post_login_redirect(request, user)

        context["errors"] = errors

    return render(request, "core/register.html", context)


@require_http_methods(["GET", "POST"])
def login_view(request):
    if request.user.is_authenticated:
        return _post_login_redirect(request, request.user)

    context = {"error": None, "email_value": "", "next": request.GET.get("next", "")}

    if request.method == "POST":
        email = (request.POST.get("email") or "").strip().lower()
        password = request.POST.get("password") or ""
        context["email_value"] = email

        user = authenticate(request, username=email, password=password)
        if user is None:
            context["error"] = "Invalid email or password."
        else:
            login(request, user)
            return _post_login_redirect(request, user)

    return render(request, "core/login.html", context)


@require_http_methods(["POST"])
def logout_view(request):
    logout(request)
    return redirect("login")
