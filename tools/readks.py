#!/usr/bin/env python
# vim: set et ai ts=4 sts=4 sw=4:
import base64
import datetime
from argparse import ArgumentParser

import jks
from jks.util import as_pem, pkey_as_pem


def get_entry_metadata(entry):
    result = f"Alias: {entry.alias}\n"
    result += f"  Type: {type(entry).__name__}\n"
    result += "  Timestamp: {}\n".format(
        datetime.datetime.fromtimestamp(entry.timestamp // 1000, tz=datetime.timezone.utc).strftime(
            "%Y-%m-%dT%H:%M:%SZ"
        )
    )

    if entry.is_decrypted():
        if isinstance(entry, jks.PrivateKeyEntry):
            result += f"  Algorithm OID: {entry.algorithm_oid}\n"
            result += f"  Certificate chain: {len(entry.cert_chain)} certificate(s)\n"
        if isinstance(entry, jks.SecretKeyEntry):
            result += f"  Algorithm: {entry.algorithm}\n"
            result += f"  Key size: {entry.key_size} bits\n"
        if isinstance(entry, jks.BksKeyEntry) or isinstance(entry, jks.BksSealedKeyEntry):
            result += f"  Key type: {jks.bks.BksKeyEntry.type2str(entry.type)}\n"
            result += f"  Key format: {entry.format}\n"
            result += f"  Key algorithm: {entry.algorithm}\n"
            if entry.type in [jks.bks.KEY_TYPE_PRIVATE, jks.bks.KEY_TYPE_PUBLIC]:
                result += f"  Key algorithm OID: {entry.algorithm_oid}\n"
            elif entry.type == jks.bks.KEY_TYPE_SECRET:
                result += f"  Key size: {entry.key_size} bits\n"
        if isinstance(entry, jks.TrustedCertEntry) or isinstance(entry, jks.bks.TrustedCertEntry):
            result += f"  Certificate type: {entry.type}\n"
    else:
        result += "  <not yet decrypted>\n"

    return result


def get_entry_bits(entry):
    if isinstance(entry, jks.PrivateKeyEntry):
        result = pkey_as_pem(entry)
        for c in entry.cert_chain:
            result += "\n" + as_pem(c[1], "CERTIFICATE")
        return result

    if isinstance(entry, jks.SecretKeyEntry):
        return base64.b64encode(entry.key)

    if isinstance(entry, jks.bks.BksKeyEntry) or isinstance(entry, jks.bks.BksSealedKeyEntry):
        if entry.type == jks.bks.KEY_TYPE_PRIVATE:
            result = pkey_as_pem(entry)
            for c in entry.cert_chain:
                result += "\n" + as_pem(c.cert, "CERTIFICATE")
            return result
        elif entry.type == jks.bks.KEY_TYPE_PUBLIC:
            return as_pem(entry.public_key_info, "PUBLIC KEY")
        elif entry.type == jks.bks.KEY_TYPE_SECRET:
            return base64.b64encode(entry.key)

    if isinstance(entry, jks.bks.BksSecretKeyEntry):
        return base64.b64encode(entry.key)

    if isinstance(entry, jks.TrustedCertEntry) or isinstance(entry, jks.bks.TrustedCertEntry):
        return as_pem(entry.cert, "CERTIFICATE")


if __name__ == "__main__":
    parser = ArgumentParser(description="Utility for reading Java keystores.")
    parser.add_argument("keystore_file")
    parser.add_argument("keystore_password")
    parser.add_argument(
        "--type",
        default="jks",
        choices=["jks", "jceks", "bks", "uber"],
        help="The type of input keystore. Defaults to 'jks'.",
    )

    group = parser.add_mutually_exclusive_group()
    group.add_argument(
        "-l",
        "--list",
        action="store_true",
        default=True,
        help="Print a list of entries/aliases in the keystore and some metadata about each one.",
    )
    group.add_argument(
        "-x",
        "--extract",
        metavar="ALIAS",
        dest="extract_alias",
        help="Extract the relevant key and/or certificates for the given alias and print them in the PEM format.",
    )
    args = parser.parse_args()

    args.type = args.type.lower()

    ks_class = jks.KeyStore
    if args.type == "bks":
        ks_class = jks.BksKeyStore
    elif args.type == "uber":
        ks_class = jks.UberKeyStore

    ks = ks_class.load(args.keystore_file, args.keystore_password)

    if args.extract_alias:
        entry = ks.entries[args.extract_alias]
        if not entry.is_decrypted():
            # call entry.decrypt("password") here
            raise Exception("Entry is still encrypted; password needed")
        print(get_entry_bits(entry))

    elif args.list:
        for _alias, entry in ks.entries.items():
            print(get_entry_metadata(entry))
