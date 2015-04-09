from django.conf.urls import *

urlpatterns = patterns('django_agent_trust.views',

    # revoke agent trust
    (r'^forget_agent/$', 'forget_agent'),
    (r'^forget_other_agents/$', 'forget_other_agents'),
)
