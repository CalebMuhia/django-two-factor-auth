from django.conf.urls import *

urlpatterns = patterns('two_factor.plugins.agent_trust.views',

    # revoke agent trust
    (r'^forget_agent/$', 'forget_agent'),
    (r'^forget_other_agents/$', 'forget_other_agents'),
)
