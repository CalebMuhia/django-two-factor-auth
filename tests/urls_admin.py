from django.conf.urls import url, include
from django.contrib import admin

from .urls import urlpatterns


admin.autodiscover()

urlpatterns += [
    url(r'^admin/', include(admin.site.urls)),
]
