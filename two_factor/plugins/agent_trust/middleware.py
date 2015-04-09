from base64 import b64encode, b64decode
from datetime import datetime
from hashlib import md5
import json
import logging
from warnings import warn

import django
from django.core.exceptions import ImproperlyConfigured, MiddlewareNotUsed

from .conf import settings
from .models import AgentSettings, Agent, SESSION_TOKEN_KEY
from .utils import load_agent, _save_agent

logger = logging.getLogger(__name__)


class AgentMiddleware(object):
    """
    This must be installed after
    :class:`~django.contrib.auth.middleware.AuthenticationMiddleware` to manage
    trusted agents.

    This middleware will set ``request.agent`` to an instance of
    :class:`django_agent_trust.models.Agent`. ``request.agent.is_trusted`` will
    tell you whether the user's agent has been trusted.
    """
    def __init__(self):
        if django.VERSION < (1, 4):
            warn('django_agent_trust requires Django 1.4 or higher')
            raise MiddlewareNotUsed()

    def process_request(self, request):
        if request.user.is_authenticated():
            AgentSettings.objects.get_or_create(user=request.user)

            agent = load_agent(request)
            if (agent.session is not None) and (agent.session != request.session.get(SESSION_TOKEN_KEY)):
                agent = Agent.untrusted_agent(request.user)
            request.agent = agent
        else:
            request.agent = Agent.untrusted_agent(request.user)

        return None

    def process_response(self, request, response):
        agent = getattr(request, 'agent', None)

        if (agent is not None) and agent.user.is_authenticated():
            _save_agent(agent, response)

        return response

