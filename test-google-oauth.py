import logging
from datetime import timezone
from json import JSONDecodeError, dump, load
from pathlib import Path
from typing import List, Optional

from google_auth_oauthlib.flow import InstalledAppFlow
from requests.adapters import HTTPAdapter
from requests_oauthlib import OAuth2Session
from urllib3.util.retry import Retry

log = logging.getLogger(__name__)

# from https://github.com/gilesknap/gphotos-sync/blob/89d988031d38cf45fe818bbb28187d614b9e4bd7/src/gphotos_sync/authorize.py#L20
class Authorize:
    def __init__(
        self,
        scope: List[str],
        token_file: Path,
        secrets_file: Path,
        max_retries: int = 5,
        port: int = 8080,
    ):
        """A very simple class to handle Google API authorization flow
        for the requests library. Includes saving the token and automatic
        token refresh.

        Args:
            scope: list of the scopes for which permission will be granted
            token_file: full path of a file in which the user token will be
            placed. After first use the previous token will also be read in from
            this file
            secrets_file: full path of the client secrets file obtained from
            Google Api Console
        """
        self.max_retries = max_retries
        self.scope: List[str] = scope
        self.token_file: Path = token_file
        self.session = None
        self.token = None
        self.secrets_file = secrets_file
        self.port = port

        try:
            with secrets_file.open("r") as stream:
                all_json = load(stream)
            secrets = all_json["installed"]
            self.client_id = secrets["client_id"]
            self.client_secret = secrets["client_secret"]
            self.redirect_uri = secrets["redirect_uris"][0]
            self.token_uri = secrets["token_uri"]
            self.extra = {
                "client_id": self.client_id,
                "client_secret": self.client_secret,
            }

        except (JSONDecodeError, IOError):
            print("missing or bad secrets file: {}".format(secrets_file))
            exit(1)

    def load_token(self) -> Optional[str]:
        try:
            with self.token_file.open("r") as stream:
                token = load(stream)
        except (JSONDecodeError, IOError):
            return None
        return token

    def save_token(self, token: str):
        with self.token_file.open("w") as stream:
            dump(token, stream)
        try:
            self.token_file.chmod(0o600)
        except (PermissionError,):
            log.warning("Could not change permissions of the token file")

    def authorize(self):
        """Initiates OAuth2 authentication and authorization flow"""
        token = self.load_token()

        if token:
            self.session = OAuth2Session(
                self.client_id,
                token=token,
                auto_refresh_url=self.token_uri,
                auto_refresh_kwargs=self.extra,
                token_updater=self.save_token,
            )
        else:
            flow = InstalledAppFlow.from_client_secrets_file(
                self.secrets_file, scopes=self.scope
            )
            # localhost and bind to 0.0.0.0 always works even in a container.
            flow.run_local_server(
                open_browser=False, bind_addr="0.0.0.0", port=self.port
            )

            self.session = flow.authorized_session()

            # Mapping for backward compatibility
            oauth2_token = {
                "access_token": flow.credentials.token,
                "refresh_token": flow.credentials.refresh_token,
                "token_type": "Bearer",
                "scope": flow.credentials.scopes,
                "expires_at": flow.credentials.expiry.replace(
                    tzinfo=timezone.utc
                ).timestamp(),
            }

            self.save_token(oauth2_token)

        # set up the retry behaviour for the authorized session
        retries = Retry(
            total=self.max_retries,
            backoff_factor=5,
            status_forcelist=[500, 502, 503, 504, 429],
            allowed_methods=frozenset(["GET", "POST"]),
            raise_on_status=False,
            respect_retry_after_header=True,
        )
        # apply the retry behaviour to our session by replacing the default HTTPAdapter
        self.session.mount("https://", HTTPAdapter(max_retries=retries))



scope = [
    "https://www.googleapis.com/auth/youtube"
]
secret_file = next(Path(".").glob("client_secret_*.apps.googleusercontent.com.json"))
credentials_file = Path("credentials.json")

port = 8080



auth = Authorize(
            scope,
            credentials_file,
            secret_file,
            int(5),
            port=port,
        )
auth.authorize()


request_handler = auth.session

import pychromecast
import sys
from pychromecast.controllers.youtube import YouTubeController

CAST_NAME = "Test"

chromecasts, browser = pychromecast.get_listed_chromecasts(
    friendly_names=[CAST_NAME]
)
if not chromecasts:
    print(f'No chromecast with name "{CAST_NAME}" discovered')
    print(chromecasts)
    sys.exit(1)

chromecast = chromecasts[0]
# Start socket client's worker thread and wait for initial status update
chromecast.wait()


media_id = "YlUKcNNmywk"
yt = YouTubeController(request_handler)
chromecast.register_handler(yt)
yt.clear_playlist()
yt.play_video(media_id)

chromecast.media_controller.play()

