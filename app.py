import os
from flask import Flask, redirect, request
from google_auth_oauthlib.flow import Flow
from itsdangerous import URLSafeSerializer

app = Flask(__name__)

CLIENT_ID = os.environ["GOOGLE_CLIENT_ID"]
CLIENT_SECRET = os.environ["GOOGLE_CLIENT_SECRET"]
REDIRECT_URI = os.environ["GOOGLE_REDIRECT_URI"]

# Production Streamlit app fallback
STREAMLIT_RETURN_URL = os.environ["STREAMLIT_RETURN_URL"].rstrip("/")

SIGNING_SECRET = os.environ["SIGNING_SECRET"]

SCOPES = [
    "https://www.googleapis.com/auth/earthengine",
    "openid",
    "https://www.googleapis.com/auth/userinfo.email",
]

serializer = URLSafeSerializer(SIGNING_SECRET, salt="oauth-return")

# Allowed Streamlit destinations
ALLOWED_RETURN_URLS = {
    STREAMLIT_RETURN_URL,
    "https://opencalvalapp-rfx3ahcnscaas7m6guvpmm.streamlit.app",
}


def make_flow(code_verifier=None):
    return Flow.from_client_config(
        {
            "web": {
                "client_id": CLIENT_ID,
                "client_secret": CLIENT_SECRET,
                "auth_uri": "https://accounts.google.com/o/oauth2/auth",
                "token_uri": "https://oauth2.googleapis.com/token",
            }
        },
        scopes=SCOPES,
        redirect_uri=REDIRECT_URI,
        code_verifier=code_verifier,
        autogenerate_code_verifier=(code_verifier is None),
    )


oauth_store = {}


@app.route("/auth/start")
def start():
    return_to = request.args.get(
        "return_to",
        STREAMLIT_RETURN_URL
    ).rstrip("/")

    if return_to not in ALLOWED_RETURN_URLS:
        return "Invalid return URL.", 400

    flow = make_flow()

    auth_url, state = flow.authorization_url(
        access_type="offline",
        include_granted_scopes="true",
        prompt="consent",
    )

    oauth_store[state] = {
        "code_verifier": flow.code_verifier,
        "return_to": return_to,
    }

    return redirect(auth_url)


@app.route("/auth/callback")
def callback():
    code = request.args.get("code")
    state = request.args.get("state")

    if state not in oauth_store:
        return "Session expired. Please try again."

    session = oauth_store.pop(state)

    code_verifier = session["code_verifier"]
    return_to = session["return_to"]

    flow = make_flow(code_verifier)
    flow.fetch_token(code=code)

    creds = flow.credentials

    payload = {
        "token": creds.token,
        "refresh_token": creds.refresh_token,
        "token_uri": creds.token_uri,
        "client_id": creds.client_id,
        "client_secret": creds.client_secret,
        "scopes": list(creds.scopes),
    }

    signed = serializer.dumps(payload)

    return redirect(
        f"{return_to}/?oauth_return={signed}"
    )
