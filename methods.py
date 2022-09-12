import json
import time

import pandas
import pandas as pd
import requests
from requests_toolbelt.multipart.encoder import MultipartEncoder


def upload(file: str, server: str, apikey: str) -> str:
    """Upload File

    Uploads file via requests POST methode to MobSF"""

    print("Uploading file")
    multipart_data = MultipartEncoder(fields={'file': (file, open(file, 'rb'), 'application/octet-stream')})
    headers = {'Content-Type': multipart_data.content_type, 'Authorization': apikey}
    response = requests.post(server + '/api/v1/upload', data=multipart_data, headers=headers)
    print(type(response.text))
    return response.text


def scan(data: str, server: str, apikey: str) -> dict:
    """Scan the file

    Lets MobSF scan the selected file previously uploaded.
    data should be the response text from upload()"""

    print("Scanning file")
    post_dict = json.loads(data)
    headers = {'Authorization': apikey}
    response = requests.post(server + '/api/v1/scan', data=post_dict, headers=headers)
    print(type(json.loads(response.text)))
    return json.loads(response.text)


def pdf(data, server, apikey):
    """Generate PDF Report"""

    print("Generate PDF report")
    headers = {'Authorization': apikey}
    data = {"hash": json.loads(data)["hash"]}
    response = requests.post(server + '/api/v1/download_pdf', data=data, headers=headers, stream=True)
    with open("report.pdf", 'wb') as flip:
        for chunk in response.iter_content(chunk_size=1024):
            if chunk:
                flip.write(chunk)
    print("Report saved as report.pdf")


def json_resp(data, server, apikey):
    """Generate JSON Report"""

    print("Generate JSON report")
    headers = {'Authorization': apikey}
    data = {"hash": json.loads(data)["hash"]}
    response = requests.post(server + '/api/v1/report_json', data=data, headers=headers)
    return json.loads(response.text)


def delete(data, server, apikey):
    """Delete Scan Result"""

    print("Deleting Scan")
    headers = {'Authorization': apikey}
    data = {"hash": json.loads(data)["hash"]}
    response = requests.post(server + '/api/v1/delete_scan', data=data, headers=headers)
    return json.loads(response.text)


def scorecard(data, server, apikey):
    """Generates the Scorecard"""

    print("Generating Scorecard")
    post_dict = json.loads(data)
    headers = {'Authorization': apikey}
    response = requests.post(server + '/api/v1/scorecard', data=post_dict, headers=headers)
    return json.loads(response.text)


def permissions2df(scan_out: dict) -> pandas.DataFrame:

    """Converts dict type POST response to pandas.DataFrame

    :param scan_out: output from scan()
    :returns: A pandas DataFrame with permissions and corresponding statuses"""

    status = []
    permissions = list(scan_out['permissions'].keys())

    for i in scan_out['permissions']:
        status.append(scan_out['permissions'][i]['status'])

    return pd.DataFrame({"permission": permissions, "status": status})


def trackers2df(scan_out: dict) -> pandas.DataFrame:
    """Converts dict type POST response to pandas.DataFrame

    :param scan_out: output from scan()
    :returns: A pandas DataFrame with trackers, corresponding categories and urls with more information"""

    name = []
    categories = []
    url = []

    for i in range(scan_out['trackers']['detected_trackers']):
        name.append(scan_out['trackers']['trackers'][i]['name'])
        categories.append(scan_out['trackers']['trackers'][i]['categories'])
        url.append(scan_out['trackers']['trackers'][i]['url'])

    return pd.DataFrame({"name": name, "categories": categories, "url": url})


def idle(seconds):
    """Lets the program wait for {seconds}"""

    print("Starting MobSF ...")
    time.sleep(seconds)
    print("Done!")


# Inspired by: https://exodus-privacy.eu.org/en/page/faq/#colors
def switch_grade(points: int) -> int:
    """Switch case for grade, based on points

    :param points: Sum of dangerous permissions or trackers.
    :returns: An int ranging from 0-4, mapped to A-E"""

    if points == 0:
        return 0
    elif points == 1:
        return 1
    elif (points == 2) | (points == 3):
        return 2
    elif points == 4:
        return 3
    elif points > 4:
        return 4
    else:
        return -1


def switch_image(grade: int) -> int:
    """Switch case for privacy-rating image

    :param grade: Mean of dangerous permissions grade and trackers grade.
    :returns: An int from 0-4, mapped to the images in grades/"""

    if grade == 0:
        return 0
    elif grade == 1:
        return 1
    elif grade == 2:
        return 2
    elif grade == 3:
        return 3
    elif grade == 4:
        return 4
    else:
        return 5
