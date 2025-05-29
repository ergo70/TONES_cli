#!/usr/bin/env python

"""Simple CLI for TONES API
This script allows users to submit an image to the TONES API for analysis,"""

import logging
import requests
from time import sleep
from http import HTTPStatus
from base64 import b64decode
from json import loads
from Crypto.Cipher import AES
from argparse import ArgumentParser

__author__ = """Ernst-Georg Schmid"""
__copyright__ = """Copyright 2025, Ernst-Georg Schmid"""
__license__ = """MIT"""
__version__ = """1.0.0"""
__status__ = """Production"""


LOGGER = logging.getLogger(__name__)

TONE_DECODED = ["""black""", """dark""", """mediterranean""",
                """mixed""", """nordic""", """celtic"""]
UNDERTONE_DECODED = {-1: """cool""",
                     0: """neutral""", 1: """warm"""}
AGE_CLASS_DECODED = {"""B""": """0-3""", """C""": """4-12""", """J""": """13-18""", """AL""": """19-35""",
                     """AH""": """36-65""", """SL""": """66+"""}
GENDER_DECODED = {"""XX""": """female""", """XY""": """male"""}
HTTP_TIMEOUT = 1
BACKOFF = 10


def submit() -> tuple:
    """Submit the image to the TONES API for analysis."""
    querystring = {"""include_gender""": f"""{arguments.gender}""".lower(),
                   """include_age""": f"""{arguments.age}""".lower()}

    files = {"""selfie""": (arguments.image, open(
        arguments.image, """rb"""), """image/jpeg""" if arguments.image.endswith('.jpg') or arguments.image.endswith('.jpeg') else """image/png""")}
    response = session.post(BASE_URL.format("""analyze"""),
                            files=files, headers=headers, params=querystring, timeout=HTTP_TIMEOUT)

    if response.status_code != HTTPStatus.ACCEPTED:
        LOGGER.error(f"Error from TONES API: %s""", response.status_code)
    else:
        data = response.json()
        id = data.get("""id""")
        if not id:
            LOGGER.error("""No ID returned from TONES API.""")
        else:
            LOGGER.info(f"""Image submitted for analysis with ID: %s""", id)
            k = data.get("""k""")
            return id, b64decode(k)


def poll(id: str, key: str):
    """Poll the TONES API for the analysis result."""
    data = None
    for backoff in range(1, BACKOFF+1):
        sleep(backoff)
        response = session.get(BASE_URL.format(
            f"""analyze/{id}"""), headers=headers, timeout=HTTP_TIMEOUT)
        if response.status_code == HTTPStatus.ACCEPTED:
            LOGGER.info(
                f"""Waiting %s second(s) for analysis to complete, ID: %s...""", backoff, id)
            continue
        if response.status_code == HTTPStatus.NOT_FOUND:
            LOGGER.error(f"""Analysis ID %s not found.""", id)
            return
        data = response.json()
        c = data.get("""prediction""")
        n = data.get("""n""")
        ttl = data.get("""ttl""")
        LOGGER.info(f"""Analysis completed, ID: %s, TTL: %s seconds""", id, ttl)
        break

    if data:
        nonce = b64decode(n)
        ciphertext = b64decode(c)
        cipher = AES.new(key, AES.MODE_CTR, nonce=nonce)
        plaintext = cipher.decrypt(ciphertext).decode("""utf-8""")

        if "error" in plaintext:
            LOGGER.error(f"""Error returned from TONES API: %s""", plaintext)
            return
        else:
            payload = loads(plaintext)

        timing = payload.get("""timing""")
        faces_detected = payload.get("""faces_detected""")
        prediction = payload.get("""prediction""")
        tone_codes = prediction.get("""tone_codes""")
        undertone_code = prediction.get("""undertone_code""")
        optionals = prediction.get("""optionals""")
        confidence = prediction.get("""confidence""")
        cost = prediction.get("""cost""")

        print(
            f"""Tone(s): {""",""".join([TONE_DECODED[tone] for tone in tone_codes])}""")
        print(
            f"""Undertone: {UNDERTONE_DECODED.get(undertone_code, "N/A")}""")
        print(f"""Timing: {timing} seconds""")
        print(f"""Faces detected: {faces_detected}""")
        if optionals:
            age_class = optionals.get("""age_class""")
            if age_class:
                print(
                    f"""Age class: {AGE_CLASS_DECODED.get(age_class, "N/A")} years""")
            gender = optionals.get("""gender""")
            if gender:
                print(f"""Gender: {GENDER_DECODED.get(gender, "N/A")}""")
        print(f"""Confidence: {confidence * 100.0:.0f}%""")
        print(f"""Cost: {cost} credits""")
        print(f"""TTL: {ttl} seconds""")
    elif backoff == BACKOFF:
        LOGGER.error(
            f"""Failed to retrieve analysis result after %s attempts.""", BACKOFF)


def budget():
    """Check the remaining call budget."""
    response = session.get(BASE_URL.format("""budget"""),
                           headers=headers, timeout=HTTP_TIMEOUT)
    if response.status_code != HTTPStatus.OK:
        LOGGER.error(f"""Error from TONES API: %s""", response.status_code)
    else:
        data = response.json()
        print(
            f"""Remaining call budget: {data.get("""budget""", """N/A""")}""")


if __name__ == """__main__""":
    logging.basicConfig(level=logging.INFO)
    argparser = ArgumentParser()
    argparser.add_argument("""image""", type=str,
                           help="""JPEG image to analyze""")
    argparser.add_argument("""-u""", """--url""", action="""store""", type=str, required=True,
                           help="""TONES URL""")
    argparser.add_argument("""-k""", """--api_key""", action="""store""", type=str, required=True,
                           help="""TONES API key""")
    argparser.add_argument("""-g""", """--gender""", action="""store_true""",
                           default=False,
                           help="""Analyze gender""")
    argparser.add_argument("""-a""", """--age""", action="""store_true""",
                           default=False,
                           help="""Analyze age""")
    arguments = argparser.parse_args()

    BASE_URL = arguments.url.rstrip('/') + """/api/v1/{}"""
    headers = {"""authorization""": f"""Bearer {arguments.api_key}"""}
    session = requests.Session()
    id, key = submit()
    poll(id, key)
    budget()
