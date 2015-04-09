from django.shortcuts import redirect
from . import revoke_agent, revoke_other_agents

from django.conf import settings

def forget_agent(request):
    revoke_agent(request)
    return redirect(request.GET.get('next', settings.URL_PREFIX))

def forget_other_agents(request):
    revoke_other_agents(request)
    return redirect(request.GET.get('next', settings.URL_PREFIX))
