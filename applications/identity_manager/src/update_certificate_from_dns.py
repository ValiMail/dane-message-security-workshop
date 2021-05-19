#!/usr/bin/env python3
"""Update cert from DNS"""
import binascii
import os
import sys

from dane_discovery.dane import DANE
from cryptography.hazmat.primitives import serialization

from idlib import Bootstrap
from dane_discovery.exceptions import TLSAError


def main():
    """Top-level logic."""
    env_required = ["DANE_ID", "APP_UID", "CRYPTO_PATH"]
    for x in env_required:
        if not os.getenv(x):
            print("Missing environment variable: {}".format(x))
            sys.exit(1)
    bootstrapper = Bootstrap(os.getenv("DANE_ID"), os.getenv("CRYPTO_PATH"), os.getenv("APP_UID"))
    print("Checking DNS identity against local private key...")
    if not bootstrapper.public_identity_is_valid():
        print("Public identity and local private key not aligned. Check TTL and try again.")
    try:
        public_cert = DANE.get_first_leaf_certificate(bootstrapper.identity_name)
        entity_cert = public_cert["certificate_association"].encode()
        dns_cert_obj = DANE.build_x509_object(binascii.unhexlify(entity_cert))
        asset = dns_cert_obj.public_bytes(serialization.Encoding.PEM)
        bootstrapper.write_pki_asset(asset, "cert")
        print("Local cert matches DNS cert.")
    except TLSAError as err:
        print("Error retrieving certificate from DNS: {}".format(err))


if __name__ == "__main__":
    main()
