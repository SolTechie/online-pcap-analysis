from django.conf.urls import patterns, include, url
import DA.views
# Uncomment the next two lines to enable the admin:
# from django.contrib import admin
# admin.autodiscover()

urlpatterns = patterns('',
    # Examples:
    # url(r'^$', 'mytask.views.home', name='home'),
    # url(r'^mytask/', include('mytask.foo.urls')),

    # Uncomment the admin/doc line below to enable admin documentation:
    # url(r'^admin/doc/', include('django.contrib.admindocs.urls')),

    # Uncomment the next line to enable the admin:
    # url(r'^admin/', include(admin.site.urls)),
    url(r'^$',DA.views.index),
    url(r'^index/$',DA.views.index),
    url(r'^analysis/$',DA.views.analysis),
)
