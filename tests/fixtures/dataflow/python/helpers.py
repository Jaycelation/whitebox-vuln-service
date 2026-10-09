import os
import shlex
import subprocess

import requests


def run_ping(target):
    os.system("ping -c 1 " + target)


def quoted_ping(target):
    os.system("ping -c 1 " + shlex.quote(target))


def archive(path):
    subprocess.call(f"tar czf /tmp/backup.tgz {path}", shell=True)


def fetch_url(url: str, timeout=5):
    return requests.get(url, timeout=timeout)
