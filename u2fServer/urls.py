"""u2fServer URL Configuration

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/1.9/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  url(r'^$', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  url(r'^$', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.conf.urls import url, include
    2. Add a URL to urlpatterns:  url(r'^blog/', include('blog.urls'))
"""
from django.conf.urls import url, include

from django.contrib import admin


urlpatterns = [
    #url(r'^admin/', admin.site.urls),
    #url(r'^learn/',include('learn.urls')),
    url(r'^u2fServer/', include('u2fserver.urls')),
    url(r'', include('u2fserver.urls')),
    # url(r'^user',include('usermanage.urls')),
    # url(r'login/enroll/$',u2fview.enroll),
    # url(r'login/sign/$',u2fview.sign),
    # url(r'register/enroll/$',u2fview.enroll),
    # url(r'register/sign/$',u2fview.sign),
    # url(r'^account/',include('account.urls')),
    #url(r'^home/', learn_views.index),  # new

    #url(r'', include('usermanage.urls')),
]
