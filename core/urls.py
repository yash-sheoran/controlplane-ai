from django.urls import path

from . import dashboard_views, views

urlpatterns = [
    path("health/", views.health_check, name="health-check"),
    path("requests/", views.create_request, name="create-request"),
    # Section 7.1 User Thumbs-Down: a plain JSON API endpoint, unlike the
    # HTML dashboard views under /dashboard/ (see core/dashboard_urls.py).
    path(
        "feedback/<uuid:trace_id>/thumbs-down/",
        dashboard_views.submit_thumbs_down,
        name="submit-thumbs-down",
    ),
]
