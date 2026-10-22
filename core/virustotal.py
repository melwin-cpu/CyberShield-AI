import os
import requests
from dotenv import load_dotenv

load_dotenv()

API_KEY = os.getenv("VT_API_KEY")

VIRUSTOTAL_BASE_URL = "https://www.virustotal.com/api/v3"


class VirusTotalError(Exception):
    """Raised when a VirusTotal API request fails."""
    pass


def check_file_hash(file_hash):
    """
    Look up a file SHA-256 hash using the VirusTotal API.

    Returns:
        dict: VirusTotal response when the hash is found.
        None: When the file hash is not found (404).

    Raises:
        VirusTotalError: For configuration, network, or API errors.
    """
    if not API_KEY:
        raise VirusTotalError(
            "VT_API_KEY is missing. Check your project's .env file."
        )

    if not file_hash or len(file_hash) != 64:
        raise VirusTotalError("Please provide a valid SHA-256 hash.")

    url = f"{VIRUSTOTAL_BASE_URL}/files/{file_hash}"
    headers = {"x-apikey": API_KEY}

    try:
        response = requests.get(
            url,
            headers=headers,
            timeout=20
        )
    except requests.RequestException as exc:
        raise VirusTotalError(
            f"Unable to connect to VirusTotal: {exc}"
        ) from exc

    if response.status_code == 200:
        return response.json()

    if response.status_code == 404:
        return None

    if response.status_code == 401:
        raise VirusTotalError(
            "VirusTotal API key is invalid or unauthorized."
        )

    if response.status_code == 403:
        raise VirusTotalError(
            "VirusTotal denied the request. Check API permissions."
        )

    if response.status_code == 429:
        raise VirusTotalError(
            "VirusTotal API rate limit reached. Try again later."
        )

    raise VirusTotalError(
        f"VirusTotal API error: HTTP {response.status_code}."
    )