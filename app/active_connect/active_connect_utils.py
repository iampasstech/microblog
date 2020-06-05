from flask import current_app
from Activeconnect.management_api import ManagementAPI


def get_management_api():
    application_id = current_app.config.get("ACTIVE_CONNECT_APPLICATION_ID")
    application_secret = current_app.config.get("ACTIVE_CONNECT_APPLICATION_SECRET")

    manager = ManagementAPI(application_id=application_id, application_secret=application_secret)
    return manager
