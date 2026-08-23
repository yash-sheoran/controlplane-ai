from django.urls import path

from . import dashboard_views

urlpatterns = [
    path("", dashboard_views.dashboard_home, name="dashboard-home"),
    path("trends/", dashboard_views.dashboard_trends, name="dashboard-trends"),
    path("human-review/", dashboard_views.human_review_queue, name="human-review-queue"),
    path("fpr-tuning/", dashboard_views.fpr_tuning, name="fpr-tuning"),
]
