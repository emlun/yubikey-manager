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

import base64
import click
import json
import logging
import os
import re
import sys

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.keywrap import (
    aes_key_unwrap,
    aes_key_wrap,
)
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
    load_der_public_key,
)
from fido2.client import ClientError, Fido2Client, UserInteraction
from fido2.ctap import CtapError
from fido2.ctap2.extensions import CredProtectExtension
from fido2.pcsc import CtapPcscDevice
from getpass import getpass
from hashlib import sha256
from smartcard.Exceptions import NoCardException, CardConnectionException
from time import sleep
from typing import Optional
from yubikit.core.fido import FidoConnection

from ..hid import list_ctap_devices
from .fido import fido
from .util import CliFail, click_prompt

logger = logging.getLogger(__name__)


DEFAULT_RP_ID = "localhost"

USER_FILE_PATH = os.path.expanduser("~/.local/share/ykman/vault-user.json")
VAULT_DIR = os.path.expanduser("~/.local/share/ykman/vault")
CURVE = ec.SECP256R1
CURVE_ORDER = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
VAULT_FILE_EXTENSION = ".vlt"


# Handle user interaction
class CliInteraction(UserInteraction):
    def __init__(self):
        self.pin = None

    def prompt_up(self):
        print("\nTouch your authenticator device now...\n")

    def request_pin(self, permissions, rd_id):
        if self.pin is None:
            self.pin = getpass("Enter PIN: ")
        return self.pin

    def request_uv(self, permissions, rd_id):
        print("User Verification required.")
        return True


def open_client(conn, rp_id):
    return Fido2Client(
        conn,
        rp_id,
        verify=lambda req_rp_id, origin: req_rp_id == origin and req_rp_id == rp_id,
        user_interaction=CliInteraction(),
    )


def rp_structure(rp_id: str) -> dict[str, str]:
    return {
        "id": rp_id,
        "name": "YubiKey Manager FIDO-backed password vault",
    }


@fido.group()
@click.pass_context
def vault(ctx):
    """
    Manage a FIDO-backed password vault.
    """

    if not "ctap2" in ctx.obj:
        ctx.fail("This security key does not support CTAP2.")

    ctap2 = ctx.obj["ctap2"]
    if not "hmac-secret" in ctap2.get_info().extensions:
        ctx.fail(
            """This security key does not support the CTAP2 "hmac-secret" extension."""
        )


def _aes_keygen():
    return AESGCM.generate_key(bit_length=128), os.urandom(16)


def choose_credential(client: Fido2Client, user_data: dict):
    choose_cred_result = client.get_assertion(
        {
            "rpId": user_data["rp_id"],
            "challenge": os.urandom(16),
            "userVerification": "discouraged",
            "allowCredentials": [
                {"type": "public-key", "id": deserialize_bytes(cred["id"])}
                for cred in user_data["fido_credentials"]
            ],
        },
    ).get_response(0)
    return choose_cred_result["credentialId"]


def derive_authenticator_key(client: Fido2Client, user_data: dict):
    cred_id = choose_credential(client, user_data)

    chosen_cred = [
        cred
        for cred in user_data["fido_credentials"]
        if cred["id"] == serialize_bytes(cred_id)
    ][0]

    assert_result = client.get_assertion(
        {
            "rpId": user_data["rp_id"],
            "challenge": os.urandom(16),
            "allowCredentials": [{"type": "public-key", "id": cred_id}],
            "userVerification": "required",
            "extensions": {
                "hmacGetSecret": {
                    "salt1": _prf_salt_to_hmac(deserialize_bytes(chosen_cred["prf_salt"])),
                }
            },
        },
    ).get_response(0)
    authnr_private_key_bytes = assert_result.extension_results["hmacGetSecret"][
        "output1"
    ]
    authnr_private_key_int = int.from_bytes(authnr_private_key_bytes, "big")
    authnr_private_key = ec.derive_private_key(authnr_private_key_int, CURVE())
    return authnr_private_key, chosen_cred["id"]


def serialize_bytes(b: bytes):
    return base64.b64encode(b).decode("utf-8")


def deserialize_bytes(s: str):
    return base64.b64decode(s.encode("utf-8"))


def serialize_public_key(pubkey: ec.EllipticCurvePublicKey):
    return serialize_bytes(
        pubkey.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
    )


def deserialize_public_key(serialized_pubkey: str):
    return load_der_public_key(deserialize_bytes(serialized_pubkey))


def _sha256(b):
    h = sha256()
    h.update(b)
    d = h.digest()

    return d


def _prf_salt_to_hmac(salt: bytes) -> bytes:
    return _sha256('WebAuthn PRF'.encode('utf-8') + bytes([0]) + salt)


def register_new_credential(
    client: Fido2Client,
    user_data: dict,
    name: Optional[str] = None,
):
    user_handle = deserialize_bytes(user_data["user_handle"])
    user = {"id": user_handle, "name": serialize_bytes(user_handle)}
    prf_salt = os.urandom(32)

    make_cred_result = client.make_credential(
        {
            "rp": rp_structure(user_data["rp_id"]),
            "user": user,
            "challenge": os.urandom(16),
            "pubKeyCredParams": [{"type": "public-key", "alg": -7}],
            "excludeCredentials": [
                {"type": "public-key", "id": deserialize_bytes(cred["id"])}
                for cred in user_data["fido_credentials"]
            ],
            "authenticatorSelection": {
                "userVerification": "required",
            },
            "extensions": {
                "hmacCreateSecret": True,
                "enforceCredentialProtectionPolicy": True,
                "credentialProtectionPolicy": CredProtectExtension.POLICY.OPTIONAL_WITH_LIST,
            },
        },
    )
    cred_id = make_cred_result[
        "attestationObject"
    ].auth_data.credential_data.credential_id

    click.echo("Success!")

    get_assertion_args = {
        "rpId": user_data["rp_id"],
        "challenge": os.urandom(16),
        "allowCredentials": [{"type": "public-key", "id": cred_id}],
        "userVerification": "required",
        "extensions": {"hmacGetSecret": {"salt1": _prf_salt_to_hmac(prf_salt)}},
    }
    assert_result = client.get_assertion(get_assertion_args).get_response(0)

    authnr_private_key_bytes = assert_result.extension_results["hmacGetSecret"][
        "output1"
    ]
    authnr_private_key_int = int.from_bytes(authnr_private_key_bytes, "big")

    if authnr_private_key_int == 0 or authnr_private_key_int >= CURVE_ORDER:
        click.echo("Generated bad wrapping key, retrying...")
        return register_new_credential(client, user_data, name)

    else:
        authnr_private_key = ec.derive_private_key(authnr_private_key_int, CURVE())

        return {
            "id": serialize_bytes(cred_id),
            "name": name,
            "prf_salt": serialize_bytes(prf_salt),
            "ecdh_pubkey": serialize_public_key(authnr_private_key.public_key()),
        }, authnr_private_key


def derive_wrapping_key(
    ecdh_prikey: ec.EllipticCurvePrivateKey,
    ecdh_pubkey: ec.EllipticCurvePublicKey,
    password_path: str,
    salt: bytes,
):
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=16,
        salt=salt,
        info=password_path.encode("utf-8"),
    )
    authnr_password_key = hkdf.derive(
        ecdh_prikey.exchange(ec.ECDH(), ecdh_pubkey)
    )
    return authnr_password_key


def generate_wrapping_key(authnr_pubkey: ec.EllipticCurvePublicKey, password_path: str):
    ecdh_key = ec.generate_private_key(CURVE())
    salt = os.urandom(16)
    return (
        derive_wrapping_key(ecdh_key, authnr_pubkey, password_path, salt),
        ecdh_key.public_key(),
        salt,
    )


def get_prompt_reinsert(conn, msg: str, nfc_msg: str):
    if isinstance(conn, CtapPcscDevice):  # NFC
        readers = list(CtapPcscDevice.list_devices())
        if not readers or readers[0].reader.name != conn._name:
            logger.error(f"Multiple readers matched: {readers}")
            raise CliFail("Unable to isolate NFC reader.")
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

        def prompt_re_insert():
            click.echo(msg)

            ignore_fingerprints = set(dev.fingerprint for dev in list_ctap_devices())
            while True:
                sleep(0.5)
                for dev in list_ctap_devices():
                    if dev.fingerprint not in ignore_fingerprints:
                        return dev.open_connection(FidoConnection)

    return prompt_re_insert


def load_user_data():
    try:
        with open(USER_FILE_PATH, "rt") as user_data_file:
            return json.load(user_data_file)

    except Exception as e:
        logger.error("Failed to read user data file.", exc_info=e)
        raise CliFail("Failed to read user data file.")


def write_user_data(user_data: dict):
    try:
        with open(USER_FILE_PATH, "wt") as user_data_file:
            json.dump(user_data, user_data_file, indent=2)

    except Exception as e:
        logger.error("Failed to write user data file.", exc_info=e)
        raise CliFail("Failed to write user data file.")


def get_all_password_files():
    for dirpath, dirnames, filenames in os.walk(VAULT_DIR):
        for filename in filenames:
            if filename.endswith(VAULT_FILE_EXTENSION):
                yield os.path.join(dirpath, filename)


def decrypt_password_key(
        password_path: str,
        authnr_key: ec.EllipticCurvePrivateKey,
        password_credential_key: dict[str, str],
) -> bytes:
    ecdh_pubkey = deserialize_public_key(password_credential_key['ecdh_pubkey'])
    salt = deserialize_bytes(password_credential_key['hkdf_salt'])
    wrapping_key = derive_wrapping_key(
        authnr_key,
        ecdh_pubkey,
        password_path,
        salt,
    )

    return aes_key_unwrap(
        wrapping_key, deserialize_bytes(password_credential_key['wrapped_key'])
    )


def encrypt_password_key(
        password_path: str,
        password_key: bytes,
        authnr_key: ec.EllipticCurvePublicKey,
) -> dict[str, str]:
    new_wrapping_key, new_ecdh_pubkey, new_salt = generate_wrapping_key(
        authnr_key, password_path)
    wrapped_password_key = aes_key_wrap(new_wrapping_key, password_key)

    return {
        'ecdh_pubkey': serialize_public_key(new_ecdh_pubkey),
        'hkdf_salt': serialize_bytes(new_salt),
        'wrapped_key': serialize_bytes(wrapped_password_key),
    }


@vault.command()
@click.pass_context
def keys(ctx):
    """
    List security keys registered to the vault.
    """

    user_data = load_user_data()
    click.echo("Registered security keys:")
    for key in user_data["fido_credentials"]:
        click.echo(f"""{key["name"] or "(unnamed)"} : {key["id"]}""")


@vault.command()
@click.option(
    "--name",
    type=str,
    default=None,
    help="Nickname for the new credential.",
    show_default=True,
)
@click.pass_context
def register(ctx, name):
    """
    Register a new FIDO security key to the vault.

    If the vault already exists, an already registered security key must be used to authenticate first.
    """

    conn = ctx.obj["conn"]

    try:
        if os.path.exists(USER_FILE_PATH):
            user_data = load_user_data()
        else:
            user_handle = os.urandom(32)
            user_data = {
                "v": 0,
                "rp_id": DEFAULT_RP_ID,
                "user_handle": serialize_bytes(user_handle),
                "fido_credentials": [],
            }

    except Exception as e:
        logger.error("Failed to read user data file.", exc_info=e)
        raise CliFail("Failed to read user data file.")

    if len(user_data["fido_credentials"]) == 0:
        client: Fido2Client = open_client(conn, user_data["rp_id"])

        try:
            credential, _ = register_new_credential(client, user_data, name=name)

        except ClientError as e:
            if e.cause.code == CtapError.ERR.NO_CREDENTIALS:
                info = client.ctap2.get_info()
                print(info)
                raise
            else:
                raise

        user_data["fido_credentials"].append(credential)

        click.echo("First security key successfully registered!")

    else:
        click.echo("")

        click.echo("Authenticate with a security key you have already registered...")
        client: Fido2Client = open_client(conn, user_data["rp_id"])
        old_authnr_key, old_cred_id = derive_authenticator_key(client, user_data)

        prompt_re_insert = get_prompt_reinsert(
            conn,
            "Plug in the new security key to register...",
            "Remove the security key from the NFC reader and place the new one to register...",
        )
        conn = prompt_re_insert()

        client: Fido2Client = open_client(conn, user_data["rp_id"])
        try:
            new_credential, new_authnr_key = register_new_credential(
                client, user_data, name=name
            )

        except ClientError as e:
            if e.cause.code == CtapError.ERR.NO_CREDENTIALS:
                info = client.ctap2.get_info()
                print(info)
                raise
            else:
                raise

        user_data["fido_credentials"].append(new_credential)

        click.echo("Security key initialized, encrypting vault to new key...")

        for password_filepath in get_all_password_files():
            with open(password_filepath) as f:
                password_contents = json.load(f)

            password_path = os.path.relpath(
                password_filepath, start=VAULT_DIR
            ).removesuffix(VAULT_FILE_EXTENSION)

            password_key = decrypt_password_key(
                password_path,
                old_authnr_key,
                password_contents["keys"][old_cred_id],
            )

            password_contents["keys"][new_credential["id"]] = encrypt_password_key(
                password_path,
                password_key,
                new_authnr_key.public_key(),
            )

            with open(password_filepath, "wt") as f:
                json.dump(password_contents, f, indent=2)

        click.echo("Security key successfully registered!")

    os.makedirs(os.path.dirname(USER_FILE_PATH), mode=0o744, exist_ok=True)
    write_user_data(user_data)


@vault.command()
@click.argument("password_path")
@click.option(
    "-l",
    "--length",
    type=int,
    default=24,
    help="Number of characters in generated password.",
    show_default=True,
)
@click.option(
    "--symbols/--no-symbols",
    default=True,
    show_default=True,
    help="Include symbols in generated password.",
)
@click.pass_context
def generate(ctx, password_path, length, symbols):
    """
    Generate a new password and store it in the vault.
    """

    password = ""
    password_regex = (
        r"[a-zA-Z][a-zA-Z0-9]+[-_!]+[a-zA-Z0-9-_!]*"
        if symbols
        else "[a-zA-Z][a-zA-Z0-9]*"
    )

    while not (len(password) == length and re.fullmatch(password_regex, password)):
        if symbols:
            password = (
                base64.b64encode(os.urandom(length))
                .decode("utf-8")
                .replace("+", "-")
                .replace("/", "_")
                .replace("=", "!")[0:length]
            )
        else:
            password = re.sub(
                "[^a-zA-Z0-9]",
                "",
                base64.b64encode(os.urandom(length)).decode("utf-8"),
            )[0:length]

    password_path = password_path.removesuffix(VAULT_FILE_EXTENSION)
    password_filepath = os.path.join(VAULT_DIR, password_path + VAULT_FILE_EXTENSION)
    password_key, iv = _aes_keygen()
    aesgcm = AESGCM(password_key)

    password_contents = {
        "content": serialize_bytes(
            aesgcm.encrypt(iv, password.encode("utf-8"), None)
        ),
        "iv": serialize_bytes(iv),
        "keys": {},
    }

    user_data = load_user_data()

    for cred in user_data["fido_credentials"]:
        authnr_pubkey = deserialize_public_key(cred["ecdh_pubkey"])
        password_contents["keys"][cred["id"]] = encrypt_password_key(
            password_path, password_key, authnr_pubkey)

    password_dirname = os.path.dirname(password_filepath)
    os.makedirs(password_dirname, exist_ok=True)
    with open(password_filepath, "wt") as f:
        json.dump(password_contents, f, indent=2)

    click.echo(f"Wrote generated password to: {password_path}")

    write_user_data(user_data)


@vault.command()
@click.option(
    "-i",
    "--identify",
    is_flag=True,
    default=False,
    help="Deregister connected security key.",
    show_default=True,
)
@click.pass_context
def deregister(ctx, identify):
    """
    Deregister a security key from the vault.
    """

    user_data = load_user_data()

    if len(user_data["fido_credentials"]) <= 1:
        ctx.fail("Cannot deregister the last security key.")

    if identify:
        client: Fido2Client = open_client(ctx.obj["conn"], user_data["rp_id"])
        cred_id = serialize_bytes(choose_credential(client, user_data))
    else:
        click.echo("Registered security keys:")
        for i, key in enumerate(user_data["fido_credentials"]):
            click.echo(f"""{i}: {key["name"] or "(unnamed)"} : {key["id"]}""")
        click.echo("q: Quit")

        choice = None
        while choice is None:
            choice = click_prompt("Enter index to deregister")

            if choice == "q":
                sys.exit(0)

            try:
                choice = int(choice)
                if choice not in range(0, len(user_data["fido_credentials"])):
                    choice = None
            finally:
                pass

        cred_id = user_data["fido_credentials"][choice]["id"]

    user_data["fido_credentials"] = [
        key for key in user_data["fido_credentials"] if key["id"] != cred_id
    ]
    write_user_data(user_data)

    for password_filepath in get_all_password_files():
        with open(password_filepath) as f:
            password_contents = json.load(f)

        del password_contents["keys"][cred_id]

        with open(password_filepath, "wt") as f:
            json.dump(password_contents, f, indent=2)

    click.echo("Successfully deregistered security key.")


@vault.command()
@click.argument("password_path")
@click.pass_context
def show(ctx, password_path):
    """
    Decrypt a password in the vault and print it to standard output.
    """

    password_path = password_path.removesuffix(VAULT_FILE_EXTENSION)
    password_filepath = os.path.join(VAULT_DIR, password_path + VAULT_FILE_EXTENSION)

    try:
        with open(password_filepath) as f:
            password_contents = json.load(f)
    except FileNotFoundError:
        click.echo(f"No such file in vault: {password_path}")
        ctx.exit(1)

    user_data = load_user_data()
    client: Fido2Client = open_client(ctx.obj["conn"], user_data["rp_id"])
    authnr_key, cred_id = derive_authenticator_key(client, user_data)

    password_key = decrypt_password_key(
        password_path,
        authnr_key,
        password_contents["keys"][cred_id],
    )
    aesgcm = AESGCM(password_key)

    password_utf8 = aesgcm.decrypt(
        deserialize_bytes(password_contents["iv"]),
        deserialize_bytes(password_contents["content"]),
        None
    )
    password = password_utf8.decode("utf-8")

    click.echo(password)


@vault.command()
def list():
    """
    Show password files in the vault.
    """
    os.execlp("tree", "tree", VAULT_DIR)


@vault.command()
def export():
    """
    Export vault for import into web app.
    """

    output = {
        'v': 0,
        'user': load_user_data(),
        'files': {
            password_filepath
            .removeprefix(VAULT_DIR)
            .removeprefix("/")
            .removesuffix(VAULT_FILE_EXTENSION):
            json.load(open(password_filepath))
            for password_filepath in get_all_password_files()
        }
    }
    click.echo(json.dumps(output))