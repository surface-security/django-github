from datetime import datetime, timedelta, timezone
import jwt
import requests


def _get_token(app_id, private_key, app_installation_id):
    payload = {
        "iat": datetime.now(tz=timezone.utc) - timedelta(seconds=60),
        "exp": datetime.now(tz=timezone.utc) + timedelta(minutes=10),
        "iss": app_id,
    }

    encoded_jwt = jwt.encode(payload, private_key, algorithm="RS256")

    response = requests.post(
        f"https://api.github.com/app/installations/{app_installation_id}/access_tokens",
        headers={
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {encoded_jwt}",
        },
        timeout=60,
    )

    return response.json().get("token")
