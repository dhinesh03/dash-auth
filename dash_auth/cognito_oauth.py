import os
from urllib.parse import quote
from typing import Optional

from oauthlib.oauth2.rfc6749.errors import InvalidGrantError, TokenExpiredError
from dash import Dash
from flask import (
    redirect,
    request,
    url_for,
    session,
    make_response,
)
from flask_dance.contrib.cognito import make_cognito_blueprint, cognito
from flask_dance.consumer import oauth_authorized
from werkzeug.routing import Map, Rule

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
        logout_url: str = None,
        public_routes: Optional[list] = None,
        # user_info_to_session_attr_mapping: dict[str, str] = None,
    ):

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
            redirect_uri_func=(
                self.redirect_uri_func if not os.environ.get("IS_LOCAL") else None
            ),
        )
        app.server.register_blueprint(cognito_bp, url_prefix=f"{dash_base_path}/login")
        super().__init__(app, public_routes=public_routes)
        # self.user_info_to_session_attr_mapping = (
        #     {"email": "email"}
        #     if user_info_to_session_attr_mapping is None
        #     else user_info_to_session_attr_mapping
        # )

        # if logout_url is not None:
        #     logout_url = (
        #         dash_base_path.removesuffix("/") + "/" + logout_url.removeprefix("/")
        #     )

        #     cognito_hostname = (
        #         f"{domain}.auth.{region}.amazoncognito.com"
        #         if region is not None
        #         else domain
        #     )

        #     @app.server.route(logout_url)
        #     def handle_logout():
        #         session.clear()
        #         post_logout_redirect = (
        #             request.host_url.removesuffix("/") + dash_base_path
        #         )
        #         cognito_logout_url = (
        #             f"https://{cognito_hostname}/logout?"
        #             + f"client_id={cognito_bp.client_id}&logout_uri={quote(post_logout_redirect)}"
        #         )

        #         response = make_response(redirect(cognito_logout_url))

        #         # Invalidate the session cookie
        #         response.set_cookie("session", "empty", max_age=-3600)
        #         return response

    def redirect_uri_func(self):
        redirect_uri = url_for("cognito.authorized", _external=True).split("/")
        redirect_uri.pop(-4)
        redirect_uri = "/".join(redirect_uri)
        logger.info(f"Redirect URI: {redirect_uri}")
        return redirect_uri

    def is_authorized(self):
        try:
            logger.info(f"is_authorized Request path: {request.path}")
            # logger.info(f"Checking if authorized: {cognito.authorized}")

            map_adapter = Map(
                [
                    Rule(x)
                    for x in [
                        url_for("cognito.login"),
                        url_for("cognito.authorized"),
                    ]
                ]
            ).bind("")
            # logger.info(f"Map adapter: {Rule(url_for("cognito.login"))}")
            if map_adapter.test(request.path):
                return True

            if not cognito.authorized or cognito.token.get("expires_in") < 0:
                # send to cognito login
                return False
            logger.info(f"Token expires in: {cognito.token.get('expires_in')}")
            # resp = cognito.get("/oauth2/userInfo")
            # assert resp.ok, resp.text

            # for (
            #     user_info_attr,
            #     session_attr,
            # ) in self.user_info_to_session_attr_mapping.items():
            #     session[session_attr] = resp.json()[user_info_attr]
            #     logger.info(
            #         f"Added {user_info_attr} as {session[session_attr]} to session"
            #     )
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
        logger.info(f"User info: {resp.json()}")
        # for (
        #     user_info_attr,
        #     session_attr,
        # ) in blueprint.user_info_to_session_attr_mapping.items():
        #     session[session_attr] = resp.json()[user_info_attr]
        #     logger.info(
        #         f"Added {user_info_attr} as {session[session_attr]} to session"
        # )
        return None
