import time
from flask import current_app, session
from itsdangerous import JSONWebSignatureSerializer, BadSignature
from Activeconnect.management_api import ManagementAPI
from Activeconnect.authentication_api import AuthenticationAPI
from Activeconnect.session import Session, Status


def get_activeconnect_credentials():
    application_id = current_app.config.get("ACTIVE_CONNECT_APPLICATION_ID")
    application_secret = current_app.config.get("ACTIVE_CONNECT_APPLICATION_SECRET")
    return application_id,application_secret


def get_management_api():
    application_id, application_secret = get_activeconnect_credentials()
    manager = ManagementAPI(application_id=application_id, application_secret=application_secret)
    return manager


def authenticate_user(active_connect_id):
    # Get the credentials required to call Activeconnect API.
    application_id, application_secret = get_activeconnect_credentials()

    # Create an Activeconnect authenticator
    authenticator = AuthenticationAPI(application_id=application_id,
                                      application_secret=application_secret)

    # Authentication is an asynchronous process, so periodically check the status.
    # Initiate the authentication process.
    ac_session = authenticator.authenticate_user(active_connect_id)

    # Wait until the authentication succeeds or fails
    while ac_session.in_progress:
        time.sleep(2)
        ac_session.get_status()

    # Return the session status.
    return ac_session


def end_session():
    session_token = session.get('ac_session')

    if session_token is not None:
        ac_session, session_user_id = decode_session_token(session_token)
        if ac_session is not None:
            ac_session.destroy()
            del session['ac_session']


def create_session_token(ac_session, user_id):
    secret_key = current_app.config["SECRET_KEY"]
    s = JSONWebSignatureSerializer(secret_key)

    session_json = Session.Schema().dumps(ac_session)

    token = s.dumps({"session": session_json, "user_id": user_id})
    return token

def decode_session_token(session_token):
    secret_key = current_app.config["SECRET_KEY"]
    s = JSONWebSignatureSerializer(secret_key)
    try:
        session_data = s.loads(session_token)
        session_json = session_data["session"]
        ac_session = Session.Schema().loads(session_json)
        user_id = session_data["user_id"]
        return ac_session, user_id

    except BadSignature:
        current_app.logger.debug("Failed to get session data.")
        return None, None


def is_user_authenticated(user_id):
    session_token = session.get('ac_session')

    if session_token is None:
        return False
    ac_session, session_user_id = decode_session_token(session_token)

    if ac_session is not None and session_user_id is not None:
        if user_id != session_user_id:
            return False
        current_status = ac_session.get_status()
        if current_status != Status.failed:
            return ac_session.active

    return False