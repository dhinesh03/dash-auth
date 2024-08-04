import os
from typing import Optional
from oauthlib.oauth2.rfc6749.errors import InvalidGrantError, TokenExpiredError
from dash import Dash
from flask import redirect, request, url_for, session
from flask_dance.contrib.cognito import make_cognito_blueprint, cognito
from flask_dance.consumer import oauth_authorized
from werkzeug.routing import Map, Rule
from .public_routes import add_public_routes
from .auth import Auth
import logging

logger = logging.getLogger()


class CognitoOAuth(Auth):
    """
    Wraps a Dash App and adds Cognito based OAuth2 authentication.
    """

    def __init__(
        self,
        app: Dash,
        domain: str,
        region=None,
        additional_scopes=None,
        public_routes: Optional[list] = None,
        dash_app_permissions: Optional[list] = None,
    ):
        self.dash_app_permissions = dash_app_permissions
        add_public_routes(app, ['/restricted'])

        dash_base_path = app.get_relative_path("")

        cognito_bp = make_cognito_blueprint(
            domain=domain,
            region=region,
            redirect_url=dash_base_path,
            scope=[
                "openid",
                "email",
                "profile",
            ]
            + (additional_scopes if additional_scopes else []),
            state=dash_base_path.strip("/"),
            redirect_uri_func=(self.redirect_uri_func if not os.environ.get("IS_LOCAL") else None),
        )
        app.server.register_blueprint(cognito_bp, url_prefix=f"{dash_base_path}/login")
        super().__init__(app, public_routes=public_routes)

        @app.server.route(f"/{dash_base_path}/restricted", methods=["GET"])
        def handle_restricted():
            return "You don't have access to this application, please contact the administrator"

    def redirect_uri_func(self):
        redirect_uri = url_for("cognito.authorized", _external=True).split("/")
        redirect_uri.pop(-4)
        redirect_uri = "/".join(redirect_uri)
        return redirect_uri

    def is_authorized(self):
        try:
            map_adapter = Map(
                [
                    Rule(x)
                    for x in [
                        url_for("cognito.login"),
                        url_for("cognito.authorized"),
                    ]
                ]
            ).bind("")

            if map_adapter.test(request.path):
                return True

            if not cognito.authorized or cognito.token.get("expires_in") < 0:
                # send to cognito login
                return False

            if len(self.dash_app_permissions) > 0:
                if session.get("email").lower() not in self.dash_app_permissions:
                    return redirect(url_for("handle_restricted"))

            return True
        except (InvalidGrantError, TokenExpiredError):
            return self.login_request()

    def login_request(self):
        # send to cognito auth page
        return redirect(url_for("cognito.login"))

    @oauth_authorized.connect
    def logged_in(blueprint, token):
        logger.info(f"Logged in with {blueprint.name}")
        session["token"] = token
        # logger.info(f"Token: {token.get('access_token')}")
        resp = blueprint.session.get("/oauth2/userInfo")
        assert resp.ok, resp.text
        user_info = resp.json()
        session["email"] = user_info["email"]
        session["name"] = user_info["name"]
        session["username"] = user_info["username"]
        return None
