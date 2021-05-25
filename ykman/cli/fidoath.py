# Copyright (c) 2021 Yubico AB
# All rights reserved.
#
#   Redistribution and use in source and binary forms, with or
#   without modification, are permitted provided that the following
#   conditions are met:
#
#    1. Redistributions of source code must retain the above copyright
#       notice, this list of conditions and the following disclaimer.
#    2. Redistributions in binary form must reproduce the above
#       copyright notice, this list of conditions and the following
#       disclaimer in the documentation and/or other materials provided
#       with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
# FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
# COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
# INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
# BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
# ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, hmac, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from fido2.client import Fido2Client
from fido2.pcsc import CtapPcscDevice
from smartcard.Exceptions import NoCardException, CardConnectionException
from time import sleep
from typing import Optional
from yubikit.core.fido import FidoConnection

from ..hid import list_ctap_devices
from .fido import fido
from .util import (
    EnumChoice,
    cli_fail,
    click_parse_b32_key,
    click_prompt,
)
from yubikit.oath import (
    CredentialData,
    OATH_TYPE,
    HASH_ALGORITHM,
    parse_b32_key,
)

import base64
import click
import json
import logging
import os
import struct
import time

logger = logging.getLogger(__name__)

click_touch_option = click.option(
    "-t", "--touch", is_flag=True, help="Require touch on YubiKey to generate code."
)

click_show_hidden_option = click.option(
    "-H", "--show-hidden", is_flag=True, help="Include hidden accounts."
)

click_password_option = click.option(
    "-p", "--password", help="Provide a password to unlock the YubiKey."
)

click_remember_option = click.option(
    "-r",
    "--remember",
    is_flag=True,
    help="Remember the password on this machine.",
)


RP_ID = "ykman+oath+fido://"
RP_STRUCTURE = {"id": RP_ID, "name": "YubiKey Manager OATH-over-FIDO"}
USER_FILE_PATH = os.path.expanduser("~/.local/share/ykman/user.json")


def open_client(conn):
    return Fido2Client(conn, "ykman+oath+fido://", verify=lambda rp_id, origin: rp_id == origin and rp_id == "ykman+oath+fido://")


@fido.group()
@click.pass_context
def fidoath(ctx):
    """
    Manage FIDO-backed OATH credentials, or generate OATH codes.
    """

    if not "ctap2" in ctx.obj:
        ctx.fail("This security key does not support CTAP2.")

    ctap2 = ctx.obj["ctap2"]
    if not "hmac-secret" in ctap2.get_info().extensions:
        ctx.fail("""This security key does not support the CTAP2 "hmac-secret" extension.""")

    ctx.obj["client"] = open_client(ctx.obj["conn"])


def _get_cipher(secret, iv):
    return Cipher(algorithms.AES(secret), modes.CBC(iv), default_backend())


def _encrypt(aes_key, cleartext):
    iv = os.urandom(16)
    cipher = _get_cipher(aes_key, iv)
    enc = cipher.encryptor()
    return iv + enc.update(cleartext) + enc.finalize()


def _decrypt(aes_key, ciphertext):
    iv, ciphertext = ciphertext[:16], ciphertext[16:]
    cipher = _get_cipher(aes_key, iv)
    dec = cipher.decryptor()
    return dec.update(ciphertext) + dec.finalize()


def _pad(msg: bytes, block_size: int = 16):
    padder = padding.PKCS7(block_size * 8).padder()
    return padder.update(msg) + padder.finalize()


def _unpad(msg: bytes, block_size: int = 16):
    unpadder = padding.PKCS7(block_size * 8).unpadder()
    return unpadder.update(msg) + unpadder.finalize()


def _aes_keygen():
    return os.urandom(16)


def decrypt_user_key(client: Fido2Client, user_data: dict, pin: Optional[str] = None):
    choose_cred_result = client.get_assertion(
        {
            "rpId": RP_ID,
            "challenge": os.urandom(16),
            "allowCredentials": [{"type": "public-key", "id": base64.b64decode(cred["id"].encode("utf-8"))} for cred in user_data["fido_credentials"]],
        },
        user_presence=False,
        pin=pin,
    ).get_response(0)
    cred_id = choose_cred_result["credentialId"]

    chosen_cred = [
        cred for cred in user_data["fido_credentials"]
        if cred["id"] == base64.b64encode(cred_id).decode("utf-8")
    ][0]

    assert_result = client.get_assertion(
        {
            "rpId": RP_ID,
            "challenge": os.urandom(16),
            "allowCredentials": [{"type": "public-key", "id": cred_id}],
            "extensions": {"hmacGetSecret": {"salt1": base64.b64decode(chosen_cred["salt"])}},
        },
        pin=pin,
    ).get_response(0)
    unwrapping_key = assert_result.extension_results["hmacGetSecret"]["output1"]
    return _decrypt(unwrapping_key, base64.b64decode(chosen_cred["user_key_enc"]))


def register_new_credential(client: Fido2Client, user_data: dict, user_key: bytes, name: Optional[str] = None, pin: Optional[str] = None):
    user_handle = base64.b64decode(user_data["user_handle"])
    user = {"id": user_handle, "name": base64.b64encode(user_handle).decode("utf-8")}
    hmac_salt = os.urandom(32)

    make_cred_result = client.make_credential(
        {
            "rp": RP_STRUCTURE,
            "user": user,
            "challenge": os.urandom(16),
            "pubKeyCredParams": [{"type": "public-key", "alg": -7}],
            "extensions": {"hmacCreateSecret": True},
        },
        pin=pin,
    )
    cred_id = make_cred_result["attestationObject"].auth_data.credential_data.credential_id

    get_assertion_args = {
        "rpId": RP_ID,
        "challenge": os.urandom(16),
        "allowCredentials": [{"type": "public-key", "id": cred_id}],
        "extensions": {"hmacGetSecret": {"salt1": hmac_salt}},
    }
    assert_result = client.get_assertion(
        get_assertion_args,
        pin=pin,
    ).get_response(0)

    wrapping_key = assert_result.extension_results["hmacGetSecret"]["output1"]
    return {
        "id": base64.b64encode(cred_id).decode("utf-8"),
        "name": name,
        "salt": base64.b64encode(hmac_salt).decode("utf-8"),
        "user_key_enc": base64.b64encode(_encrypt(wrapping_key, user_key)).decode("utf-8"),
    }


def _sha256(msg: bytes):
    digest = hashes.Hash(hashes.SHA256())
    digest.update(msg)
    return digest.finalize()


def get_prompt_reinsert(conn, msg: str, nfc_msg: str):
    if isinstance(conn, CtapPcscDevice):  # NFC
        readers = list_ccid(conn._name)
        if not readers or readers[0].reader.name != conn._name:
            logger.error(f"Multiple readers matched: {readers}")
            cli_fail("Unable to isolate NFC reader.")
        dev = readers[0]
        logger.debug(f"use: {dev}")

        def prompt_re_insert():
            click.echo(nfc_msg)

            removed = False
            while True:
                sleep(0.5)
                try:
                    with dev.open_connection(FidoConnection):
                        if removed:
                            sleep(1.0)  # Wait for the device to settle
                            break
                except CardConnectionException:
                    pass  # Expected, ignore
                except NoCardException:
                    removed = True
            return dev.open_connection(FidoConnection)

    else:  # USB
        n_keys = len(list_ctap_devices())
        if n_keys > 1:
            cli_fail("Only one security key may be connected!")

        def prompt_re_insert():
            click.echo(msg)

            removed = False
            while True:
                sleep(0.5)
                keys = list_ctap_devices()
                if not keys:
                    removed = True
                if removed and len(keys) == 1:
                    return keys[0].open_connection(FidoConnection)

    return prompt_re_insert


def decrypt_vault(user_key: bytes, user_data: dict):
    if "vault" in user_data:
        vault_bytes = _unpad(_decrypt(user_key, base64.b64decode(user_data["vault"])))
        return json.loads(vault_bytes)
    else:
        return []


def encrypt_vault(user_key: bytes, vault: list[dict]):
    vault_str = json.dumps(vault, indent=None, separators=(",", ":"), sort_keys=True)
    enc_vault = _encrypt(user_key, _pad(vault_str.encode("utf-8")))
    return base64.b64encode(enc_vault).decode("utf-8")


def load_user_data():
    try:
        with open(USER_FILE_PATH, "rt") as user_data_file:
            return json.load(user_data_file)

    except Exception as e:
        logger.error("Failed to read user data file.", exc_info=e)
        cli_fail("Failed to read user data file.")


def write_user_data(user_key: bytes, user_data: dict, vault: list[dict]):
    try:
        with open(USER_FILE_PATH, "wt") as user_data_file:
            user_data["vault"] = encrypt_vault(user_key, vault)
            json.dump(user_data, user_data_file, indent=2)

    except Exception as e:
        logger.error("Failed to read user data file.", exc_info=e)
        cli_fail("Failed to read user data file.")


@fidoath.command()
@click.option("--name", type=str, default=None, help="Nickname for the new credential.", show_default=True)
@click_touch_option
@click.pass_context
def register(ctx, name, touch):
    """
    Register a new FIDO security key to the OATH vault.

    If the vault already exists, an already registered security key must be used to authenticate first.
    """

    conn = ctx.obj["conn"]

    try:
        if os.path.exists(USER_FILE_PATH):
            with open(USER_FILE_PATH) as user_data_file:
                user_data = json.load(user_data_file)
        else:
            user_handle = os.urandom(32)
            user_data = {
                "v": 0,
                "user_handle": base64.b64encode(user_handle).decode("utf-8"),
                "fido_credentials": [],
            }

    except Exception as e:
        logger.error("Failed to read user data file.", exc_info=e)
        cli_fail("Failed to read user data file.")

    pin = None

    if len(user_data["fido_credentials"]) == 0:
        user_key = os.urandom(16)

        client: Fido2Client = ctx.obj["client"]
        credential = register_new_credential(client, user_data, user_key, name=name)
        user_data["fido_credentials"].append(credential)

        click.echo("User key generated and first security key successfully registered.")

    else:
        click.echo("")

        prompt_re_insert = get_prompt_reinsert(
            conn,
            "Unplug all security keys, then plug in a security key you have already registered...",
            "Remove the security key from the NFC reader and place one you have already registered...")
        conn = prompt_re_insert()
        client: Fido2Client = open_client(conn)
        user_key = decrypt_user_key(client, user_data)

        prompt_re_insert = get_prompt_reinsert(
            conn,
            "Unplug the security key, then plug in the new one to register...",
            "Remove the security key from the NFC reader and place the new one to register...")
        conn = prompt_re_insert()

        client: Fido2Client = open_client(conn)
        credential = register_new_credential(client, user_data, user_key, name=name)
        user_data["fido_credentials"].append(credential)

        click.echo("Security key successfully registered!")

    os.makedirs(os.path.dirname(USER_FILE_PATH), mode=0o744, exist_ok=True)
    with open(USER_FILE_PATH, "wt") as user_data_file:
        json.dump(user_data, user_data_file, indent=2)


@fidoath.command()
@click.pass_context
def showkey(ctx):
    """
    Decrypt and show the user key.
    """

    user_data = load_user_data()
    user_key = decrypt_user_key(ctx.obj["client"], user_data)
    print(user_key)


@fidoath.command()
@click.pass_context
def showvault(ctx):
    """
    Decrypt and show the vault.
    """

    user_data = load_user_data()
    user_key = decrypt_user_key(ctx.obj["client"], user_data)
    vault = decrypt_vault(user_key, user_data)
    print(json.dumps(vault, indent=2, sort_keys=True))

@fidoath.command()
@click.argument("name")
@click.argument("secret", callback=click_parse_b32_key, required=False)
@click.option("-d", "--digits", type=click.Choice(["6", "7", "8"]), default="6", help="Number of digits in generated code.", show_default=True)
@click.option("-a", "--algorithm", type=EnumChoice(HASH_ALGORITHM), default=HASH_ALGORITHM.SHA1.name, show_default=True, help="Algorithm to use for code generation.")
@click.option("-i", "--issuer", help="Issuer of the account.")
@click.option("-p", "--period", help="Number of seconds a TOTP code is valid.", default=30, show_default=True)
@click_touch_option
@click_password_option
@click_remember_option
@click.pass_context
def add(ctx, secret, name, issuer, period, digits, touch, algorithm, password, remember):
    """
    Add a new OATH credential.
    """

    digits = int(digits)

    if not secret:
        while True:
            secret = click_prompt("Enter a secret key (base32)")
            try:
                secret = parse_b32_key(secret)
                break
            except Exception as e:
                click.echo(e)
    
    cd = CredentialData(
        name, OATH_TYPE.TOTP, algorithm, secret, digits, period, issuer=issuer
    )

    user_data = load_user_data()
    user_key = decrypt_user_key(ctx.obj["client"], user_data)
    vault = decrypt_vault(user_key, user_data)

    oath_credential = {
        "name": name,
        "alg": algorithm,
        "secret": base64.b64encode(secret).decode("utf-8"),
        "digits": digits,
        "period": period,
        "issuer": issuer,
    }
    vault.append(oath_credential)

    write_user_data(user_key, user_data, vault)


@fidoath.command()
@click_show_hidden_option
@click.pass_context
@click.option("-o", "--oath-type", is_flag=True, help="Display the OATH type.")
@click.option("-p", "--period", is_flag=True, help="Display the period.")
def list(ctx, show_hidden, oath_type, period):
    """
    List OATH credentials stored in the vault.
    """

    user_data = load_user_data()
    user_key = decrypt_user_key(ctx.obj["client"], user_data)
    vault = decrypt_vault(user_key, user_data)

    for cred in vault:
        print(cred["name"])


def dynamic_truncation(b: bytes):
    offset = b[-1] & 0x0f
    P = b[offset:offset+4]
    return bytes([P[0] & 0x7f]) + P[1:]

def generate_otp(secret: bytes, period: int, digits: int):
    h = hmac.HMAC(secret, hashes.SHA1())
    h.update(struct.pack(">Q", int(time.time()) // period))
    digest = h.finalize()
    Sbits = dynamic_truncation(digest)
    (Snum,) = struct.unpack(">I", Sbits)
    D = Snum % (10**digits)
    return str(D).rjust(digits, "0")


@fidoath.command()
@click_show_hidden_option
@click.pass_context
@click.argument("query", required=False, default="")
def code(ctx, show_hidden, query):
    """
    Generate codes.

    Generate codes from OATH accounts stored in the vault.
    Provide a query string to match one or more specific accounts.
    """

    user_data = load_user_data()
    user_key = decrypt_user_key(ctx.obj["client"], user_data)
    vault = decrypt_vault(user_key, user_data)

    creds = [
        cred for cred in vault
        if query in cred["name"]
    ]

    outputs = []
    for cred in creds:
        code = generate_otp(base64.b64decode(cred["secret"]), cred["period"], cred["digits"])
        outputs.append((cred["name"], code))

    longest_name = max(len(n) for (n, c) in outputs) if outputs else 0
    longest_code = max(len(c) for (n, c) in outputs) if outputs else 0
    format_str = "{:<%d}  {:>%d}" % (longest_name, longest_code)

    for name, result in outputs:
        click.echo(format_str.format(name, result))
