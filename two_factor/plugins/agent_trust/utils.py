from base64 import b64encode, b64decode
from datetime import datetime
from hashlib import md5
import json
import logging
from warnings import warn

from django.core.exceptions import ImproperlyConfigured, MiddlewareNotUsed

from .conf import settings
from .models import AgentSettings, Agent, SESSION_TOKEN_KEY

logger = logging.getLogger(__name__)

def load_agent(request, user=None):
    if request.user.is_authenticated():
        user = request.user
    elif user:
        logger.debug("unauthenticated, user = %s" % (user,))
    else:
        return None

    cookie_name = _cookie_name(_get_username(user))
    max_age = _max_cookie_age(user)

    # 'e30=' is base64 for '{}'
    encoded = request.get_signed_cookie(cookie_name, default='e30=',
                                        max_age=max_age)

    agent = _decode_cookie(encoded, user)

    return agent

def _save_agent(agent, response):
    logger.debug('Saving agent: username={0}, is_trusted={1}, trusted_at={2}, serial={3}'.format(
            _get_username(agent.user), agent.is_trusted, agent.trusted_at,
            agent.serial)
                 )

    cookie_name = _cookie_name(_get_username(agent.user))
    encoded = _encode_cookie(agent, agent.user)
    max_age = _max_cookie_age(agent.user)

    response.set_signed_cookie(cookie_name, encoded, max_age=max_age,
                               path=settings.AGENT_COOKIE_PATH,
                               domain=settings.AGENT_COOKIE_DOMAIN,
                               secure=settings.AGENT_COOKIE_SECURE,
                               httponly=settings.AGENT_COOKIE_HTTPONLY)

def _decode_cookie(encoded, user):
    agent = None

    content = b64decode(encoded.encode('utf-8')).decode('utf-8')
    data = json.loads(content)

    logger.debug('Decoded agent: {0}'.format(data))

    if data.get('username') == _get_username(user):
        agent = Agent.from_jsonable(data, user)
    if agent and _should_discard_agent(agent):
        agent = None

    if agent is None:
        agent = Agent.untrusted_agent(user)

    logger.debug('Loaded agent: username={0}, is_trusted={1}, trusted_at={2}, serial={3}'.format(
            _get_username(user), agent.is_trusted, agent.trusted_at,
            agent.serial)
                 )

    return agent

def _should_discard_agent(agent):
    expiration = agent.trust_expiration
    if (expiration is not None) and (expiration < datetime.now()):
        return True

    agentsettings = AgentSettings.objects.get_or_create(user=agent.user)[0]

    if agent.serial < agentsettings.serial:
        return True

    return False

def _encode_cookie(agent, user):
    data = agent.to_jsonable()
    content = json.dumps(data)
    encoded = b64encode(content.encode('utf-8')).decode('utf-8')

    return encoded

def _cookie_name(username):
    suffix = md5(username.encode('utf-8')).hexdigest()[16:]

    return '{0}-{1}'.format(settings.AGENT_COOKIE_NAME, suffix)

def _max_cookie_age(user):
    """
    Returns the max cookie age based on inactivity limits.
    """
    agentsettings = AgentSettings.objects.get_or_create(user=user)[0]

    days = settings.AGENT_INACTIVITY_DAYS

    try:
        int(days) * 86400
    except Exception:
        raise ImproperlyConfigured('AGENT_INACTIVITY_DAYS must be a number.')

    user_days = agentsettings.inactivity_days
    if (user_days is not None) and (user_days < days):
        days = user_days

    return days * 86400

def _get_username(user):
    """
    Return the username of a user in a model- and version-indepenedent way.
    """
    return user.get_username() if hasattr(user, 'get_username') else user.username
