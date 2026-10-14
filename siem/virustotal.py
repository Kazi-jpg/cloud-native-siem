"""VirusTotal lookups, file uploads, and scan polling."""

import base64
import hashlib
import os
import time

import requests


def sha256_file(file_path):
    sha256 = hashlib.sha256()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            sha256.update(chunk)
    return sha256.hexdigest()

def url_to_id(url):
    return base64.urlsafe_b64encode(url.encode()).decode().strip("=")


def analyze_url(url, api_key):
    headers = {"x-apikey": api_key}

    # Step 1: try to get an existing VirusTotal report
    url_id = url_to_id(url)
    report_endpoint = f"https://www.virustotal.com/api/v3/urls/{url_id}"

    response = requests.get(report_endpoint, headers=headers, timeout=30)

    if response.status_code == 200:
        return response.json()

    # Bad API key / auth issue
    if response.status_code == 401:
        raise Exception("VirusTotal API authentication failed. Check your API key in config.yaml.")

    # Step 2: if report doesn't exist yet, submit URL for scanning
    if response.status_code == 404:
        scan_endpoint = "https://www.virustotal.com/api/v3/urls"
        scan_response = requests.post(
            scan_endpoint,
            headers=headers,
            data={"url": url},
            timeout=30
        )

        if scan_response.status_code == 401:
            raise Exception("VirusTotal API authentication failed during URL submission. Check your API key in config.yaml.")

        scan_response.raise_for_status()

        analysis_id = scan_response.json()["data"]["id"]
        analysis_endpoint = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"

        # Step 3: poll until analysis is complete
        max_attempts = 20
        wait_seconds = 5

        for attempt in range(max_attempts):
            analysis_response = requests.get(analysis_endpoint, headers=headers, timeout=30)

            if analysis_response.status_code == 401:
                raise Exception("VirusTotal API authentication failed while polling analysis results.")

            analysis_response.raise_for_status()

            analysis_data = analysis_response.json()
            status = analysis_data["data"]["attributes"]["status"]

            print(f"VirusTotal scan status: {status} (attempt {attempt + 1}/{max_attempts})")

            if status == "completed":
                final_report = requests.get(report_endpoint, headers=headers, timeout=30)

                if final_report.status_code == 401:
                    raise Exception("VirusTotal API authentication failed while retrieving final report.")

                final_report.raise_for_status()
                return final_report.json()

            time.sleep(wait_seconds)

        raise Exception("VirusTotal analysis did not finish in time after waiting longer than expected.")

    # Step 4: raise anything else normally
    response.raise_for_status()


def analyze_file(file_path, api_key):
    headers = {"x-apikey": api_key}

    if not os.path.exists(file_path):
        raise Exception("File not found.")

    file_size = os.path.getsize(file_path)

    # VirusTotal uses a different upload flow for files over 32 MB
    if file_size > 32 * 1024 * 1024:
        upload_url_resp = requests.get(
            "https://www.virustotal.com/api/v3/files/upload_url",
            headers=headers,
            timeout=30
        )
        upload_url_resp.raise_for_status()
        upload_url = upload_url_resp.json()["data"]
    else:
        upload_url = "https://www.virustotal.com/api/v3/files"

    with open(file_path, "rb") as f:
        files = {"file": (os.path.basename(file_path), f)}
        upload_resp = requests.post(upload_url, headers=headers, files=files, timeout=60)
        upload_resp.raise_for_status()

    analysis_id = upload_resp.json()["data"]["id"]
    analysis_endpoint = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"

    max_attempts = 20
    wait_seconds = 5

    for attempt in range(max_attempts):
        analysis_response = requests.get(analysis_endpoint, headers=headers, timeout=30)
        analysis_response.raise_for_status()

        analysis_data = analysis_response.json()
        status = analysis_data["data"]["attributes"]["status"]

        print(f"VirusTotal file scan status: {status} (attempt {attempt + 1}/{max_attempts})")

        if status == "completed":
            file_hash = sha256_file(file_path)
            file_report_endpoint = f"https://www.virustotal.com/api/v3/files/{file_hash}"
            final_report = requests.get(file_report_endpoint, headers=headers, timeout=30)
            final_report.raise_for_status()
            return final_report.json(), file_hash

        time.sleep(wait_seconds)

    raise Exception("VirusTotal file analysis did not finish in time.")
