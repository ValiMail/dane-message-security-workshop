#!/usr/bin/env python3
"""Event ingestion."""
import base64
import datetime
import json
import os
import queue
import socket
import sys
import time
import threading

import dns
import dns.resolver
from paho.mqtt import client as mqtt
from dane_discovery.exceptions import TLSAError
from dane_jwe_jws.authentication import Authentication
from dane_jwe_jws.encryption import Encryption
from dane_jwe_jws.util import Util
from jwcrypto import jws
from jwcrypto.jws import InvalidJWSSignature
from jwcrypto.jws import InvalidJWSObject

from idlib import Bootstrap


ENCRYPTED_MESSAGES = queue.Queue(1024)
DECRYPTED_MESSAGES = queue.Queue(1024)
AUTHENTICATED_MESSAGES = queue.Queue(1024)
VALID_SENDERS = set([])
MY_TOPIC = ""
MAX_MESSAGE_SIZE = int(os.getenv("MAX_MESSAGE_SIZE", 4096))
BAIL = False
CACHE_FILE_PATH = os.getenv("CACHE_FILE_PATH", "/var/cache.txt")
ALLOWED_DOMAINS = []


def main():
    """Ingestion process wrapper."""
    print("STARTING EVENT INGESTION PROCESS")
    config = get_config()
    global ENCRYPTED_MESSAGES
    global DECRYPTED_MESSAGES
    global AUTHENTICATED_MESSAGES
    global VALID_SENDERS
    global MY_TOPIC
    global ALLOWED_DOMAINS
    MY_TOPIC = config["dane_id"]

    # Create tuples sets for threads
    ingest_args = (config["mqtt_host"], config["mqtt_port"])
    decrypt_args = (config["crypto_path"], config["dane_id"])
    # Create thread objects
    ingest_thread = threading.Thread(target=mqtt_ingestion_thread,
                                     name="MQTT-Ingest", args=(ingest_args))
    decrypt_thread = threading.Thread(target=message_decryption_thread,
                                      name="Decryption", args=(decrypt_args))
    auth_thread = threading.Thread(target=message_authentication_thread,
                                   name="Authentication")
    pipe_forwarder_thread = threading.Thread(target=message_printer,
                                             name="Forwarder")

    # Kick off threads
    ingest_thread.start()
    decrypt_thread.start()
    auth_thread.start()
    pipe_forwarder_thread.start()
    set_allowed_domains()
    while True:
        global BAIL
        threads = [ingest_thread, decrypt_thread, auth_thread,
                   pipe_forwarder_thread]
        print("MQTT broker at {} on port {}".format(config["mqtt_host"],
                                                    config["mqtt_port"]))
        print("Encrypted queue size: {}".format(ENCRYPTED_MESSAGES.qsize()))
        print("Decrypted queue size: {}".format(ENCRYPTED_MESSAGES.qsize()))
        print("Auth'd queue size: {}".format(AUTHENTICATED_MESSAGES.qsize()))

        print("Thread health:")
        for thread in threads:
            print("\t{} is alive: {}".format(thread.name, thread.is_alive()))
            if not thread.is_alive():
                print("\tThread {} is dead, bailing out.".format(thread.name))
                BAIL = True
        if BAIL is True:
            break
        time.sleep(60)
    print("Cleaning up!")
    for thread in threads:
        thread.join(30)
    sys.exit(0)

def set_allowed_domains():
    """Set global for allowed sender domains."""
    global ALLOWED_DOMAINS
    with open("/etc/allowed_domains.txt", "r") as permit_file:
        for line in permit_file.readlines():
            if is_a_valid_domain_name(line):
                ALLOWED_DOMAINS.append(line)


def mqtt_message_callback(client, userdata, msg):
    """Handle messages from MQTT."""
    global ENCRYPTED_MESSAGES
    global MAX_MESSAGE_SIZE
    global BAIL
    if BAIL:
        print("Bailing out of ingestion thread...")
        client.loop_stop()
    print("New message on topic: {}".format(msg.topic))
    try:
        if len(msg.payload) > MAX_MESSAGE_SIZE:
            raise ValueError("Message size is too large")
        ENCRYPTED_MESSAGES.put(msg.payload)
    except ValueError as e:
        print(e)


def mqtt_subscribe_callback(client, userdata, mid, granted_qos):
    """Handle messages from MQTT."""
    print("MQTT subscription active.")


def mqtt_connect_callback(client, userdata, flags, rc):
    """Handle messages from MQTT."""
    global MY_TOPIC
    print("MQTT connection established with {}".format(str(rc)))
    client.subscribe(MY_TOPIC)


def mqtt_ingestion_thread(hostname, port):
    """Maintain MQTT connection, drop messages into internal queue."""
    mqtt_client = mqtt.Client()
    mqtt_client.on_connect = mqtt_connect_callback
    mqtt_client.on_message = mqtt_message_callback
    mqtt_client.on_subscribe = mqtt_subscribe_callback
    mqtt_client.connect(hostname, int(port), 60)
    mqtt_client.loop_forever()


def message_decryption_thread(crypto_path, id_name):
    """Get messages from queue of encrypted messages, place in auth queue."""
    global ENCRYPTED_MESSAGES
    global BAIL
    crypto = Bootstrap(id_name, crypto_path, os.getenv("APP_UID"))
    while True:
        if BAIL:
            print("Bailing out of decryption thread.")
            break
        if not crypto.public_identity_is_valid():
            print("Public identity is not valid!")
            print("Ensure that your identity is provisioned at {}".format(id_name))
            time.sleep(10)
            continue
        priv = crypto.get_path_for_pki_asset("key")
        content = ENCRYPTED_MESSAGES.get()
        try:
            decrypted = Encryption.decrypt(content, priv)
            DECRYPTED_MESSAGES.put(decrypted)
            print("Message decrypted")
        except ValueError as err:
            print("Error in decryption: {}".format(err))
            continue


def message_authentication_thread():
    """Get messages from decrypted queue, auth and drop to filebeat socket."""
    global DECRYPTED_MESSAGES
    global AUTHENTICATED_MESSAGES
    global VALID_SENDERS
    global BAIL
    global CACHE_FILE_PATH
    while True:
        if BAIL:
            print("Bailing out of authentication thread.")
            break
        content = DECRYPTED_MESSAGES.get()
        try:
            contents = message_is_authentic(content)
            if not contents:
                continue
            jwstoken = jws.JWS()
            jwstoken.deserialize(content)
            dns_uri = jwstoken.jose_header["x5u"]
            sender_id = Util.get_name_from_dns_uri(dns_uri)
            print("Message is authentic from {}".format(sender_id))
            message = "{} says: {}".format(sender_id, contents.decode())
            update_cache_file(message, CACHE_FILE_PATH)
            AUTHENTICATED_MESSAGES.put(json.dumps(message))
        except InvalidJWSSignature as err:
            print("Failed to authenticate! ({})".format(err))
        except InvalidJWSObject as err:
            print("Unable to load JWS object: {}".format(err))


def message_is_authentic(content):
    """Return message contents if the message is authentic, else None.

    Args:
        message (str): JWS string.

    Return:
        str: Actual message if message authenticates, or an empty
            string otherwise.
    """
    global DECRYPTED_MESSAGES
    try:
        return Authentication.verify(content)
    except dns.exception.Timeout:
        print("DNS Timeout, re-queue message...")
        time.sleep(1)
        DECRYPTED_MESSAGES.put(content)
    except TLSAError as err:
        errstr = str(err)
        msg = "Error surfaced (TLSAError) and caught: {}".format(err)
        bad_id_msgs = ["The DNS query name does not exist",
                       "does not contain an answer to the question"]
        for bad_msg in bad_id_msgs:
            if bad_msg in errstr:
                msg = ("Invalid ID, cannot authenticate. "
                       "Message rejected.")
        print(msg)
    return ""

def update_cache_file(message, file_path):
    """Append message cache file."""
    with open(file_path, "a") as f:
        update_line = "{}|{}".format(datetime.datetime.now().isoformat(), base64.b64encode(message))
        f.write(update_line)


def message_printer():
    """Dequeue decrypted messages, write to stdout."""
    global AUTHENTICATED_MESSAGES
    global BAIL
    while True:
        if BAIL:
            print("Bailing out of message_printer thread.")
            break
        message = AUTHENTICATED_MESSAGES.get()
        print(message)


def get_config():
    """Return app configuration from environment variables.

    Use the var_names variable to manage what's grabbed
    from environment variables.

    Return:
        dict.
    """
    var_names = ["dane_id", "crypto_path", "mqtt_host",
                 "mqtt_port"]
    config = {}
    for x in var_names:
        config[x] = os.getenv(x.upper())
    for k, v in config.items():
        if v is None:
            print("Missing essential configuration: {}".format(k.upper()))
    if None in config.values():
        time.sleep(30)
        sys.exit(1)
    return config

def domain_str_to_labels(domain_name):
    """Return a list of domain name labels, in reverse-DNS order."""
    labels = domain_name.rstrip(".").split(".")
    labels.reverse()
    return labels

def dnsname_in_domain(dns_name, domain_name):
    """Return True if dns_name falls under domain_name, else False.
    
    Forces to lowercase for comparison, since DNS is case-insensitive
    """
    dns_name_parts = domain_str_to_labels(dns_name.lower())
    domain_name_parts = domain_str_to_labels(domain_name.lower())
    if len(dns_name_parts) <= len(domain_name_parts):
        # Not enough labels to be a subdomain
        return False
    for domain_label in domain_name_parts:
        # Walk down the hierarchy, matching labels
        dns_label = dns_name_parts.pop(0)
        if dns_label != domain_label:
            return False
    return True

def is_a_valid_domain_name(domain_name):
    """Return True if domain is valid.
     We check that all labels are 63 characters or less, and
    the entire domain name is no more than 253 characters.
    """
    label_representation = domain_str_to_labels(domain_name)
    for label in label_representation:
        if len(label) >= 63:
            return False
    if len(domain_name) > 253:
        return False
    for unallowed in ["/", "\\", ":"]:
        if unallowed in domain_name:
            return False
    return True


if __name__ == "__main__":
    main()
