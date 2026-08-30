from django.urls import path

from . import dashboard_views

urlpatterns = [
    path("playground/", dashboard_views.playground, name="playground"),
    path(
        "playground/pending-status/", dashboard_views.playground_pending_status,
        name="playground-pending-status",
    ),
    path("", dashboard_views.dashboard_home, name="dashboard-home"),
    path("trends/", dashboard_views.dashboard_trends, name="dashboard-trends"),
    path("human-review/", dashboard_views.human_review_queue, name="human-review-queue"),
    path("fpr-tuning/", dashboard_views.fpr_tuning, name="fpr-tuning"),
]
