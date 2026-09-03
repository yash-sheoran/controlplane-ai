"""
URL configuration for controlplane project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/5.1/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import include, path
from django.views.generic import RedirectView

urlpatterns = [
    path('admin/', admin.site.urls),
    path('api/', include('core.urls')),
    path('dashboard/', include('core.dashboard_urls')),
    path('accounts/', include('core.auth_urls')),
    # The bare domain had no route at all, so '/' returned a bare 404 —
    # the first thing anyone given the deployed link actually sees.
    # Send it to the Playground, which is the app's real entry point;
    # @login_required bounces an unauthenticated visitor on to the login
    # page, so this lands both cases somewhere useful.
    path('', RedirectView.as_view(pattern_name='playground', permanent=False)),
]
