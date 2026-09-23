purejks
=======

[![PyPI](https://img.shields.io/pypi/v/purejks.svg)](https://pypi.org/project/purejks/)
[![CI](https://github.com/hugues31/purejks/actions/workflows/ci.yml/badge.svg)](https://github.com/hugues31/purejks/actions/workflows/ci.yml)

A pure-Python Java KeyStore file parser, including private/secret key decryption.
Can read JKS, JCEKS, BKS and UBER (BouncyCastle) key stores.

**purejks is a fork of [pyjks](https://github.com/kurtbrose/pyjks)** that installs
without a C compiler. pyjks depends on the [`twofish`](https://pypi.org/project/twofish/)
package, which is only published as a source distribution containing a C extension:
installing pyjks therefore requires `cc`, which is often missing from slim Docker images
and CI runners. Moreover, that package uses the `imp` module, removed in Python 3.12, so
reading UBER keystores with pyjks fails on recent Pythons.

purejks replaces it with a bundled, pure-Python Twofish implementation (derived from
[K-Czaplicki/TwoFish](https://github.com/K-Czaplicki/TwoFish) and optimized), and ships
as a universal `py3-none-any` wheel. All other dependencies provide wheels or are pure Python.

The import name is unchanged (`import jks`), so purejks is a drop-in replacement:
uninstall `pyjks` and install `purejks` (do not install both, they provide the same module).

```console
pip uninstall pyjks
pip install purejks
```

The best way to utilize a certificate stored in a jks file up to this point has been
to use the java keytool command to transform to pkcs12, and then openssl to transform to pem.

This is better:
 -  no security concerns in passwords going into command line arguments, or unencrypted files being left around
 -  no dependency on a JVM
 -  no compiler needed to install it

## Requirements:

 * Python 3.9+
 * pyasn1 0.3.5+
 * pyasn1_modules
 * javaobj-py3
 * pycryptodomex

## Development

The project uses [uv](https://docs.astral.sh/uv/), [ruff](https://docs.astral.sh/ruff/)
and [ty](https://docs.astral.sh/ty/):

```console
uv sync
uv run pytest
uv run ruff check . && uv run ruff format --check .
uv run ty check
```

Releases are published to PyPI by GitHub Actions (trusted publishing) when a
GitHub release is published; the tag must match the version in `pyproject.toml` (`v1.0.0`).

## Usage examples:

Reading a JKS or JCEKS keystore and dumping out its contents in the PEM format:
```python
import sys, base64, textwrap
import jks

def print_pem(der_bytes, type):
    print("-----BEGIN %s-----" % type)
    print("\r\n".join(textwrap.wrap(base64.b64encode(der_bytes).decode('ascii'), 64)))
    print("-----END %s-----" % type)

ks = jks.KeyStore.load("keystore.jks", "XXXXXXXX")
# if any of the keys in the store use a password that is not the same as the store password:
# ks.entries["key1"].decrypt("key_password")

for alias, pk in ks.private_keys.items():
    print("Private key: %s" % pk.alias)
    if pk.algorithm_oid == jks.util.RSA_ENCRYPTION_OID:
        print_pem(pk.pkey, "RSA PRIVATE KEY")
    else:
        print_pem(pk.pkey_pkcs8, "PRIVATE KEY")

    for c in pk.cert_chain:
        print_pem(c[1], "CERTIFICATE")
    print()

for alias, c in ks.certs.items():
    print("Certificate: %s" % c.alias)
    print_pem(c.cert, "CERTIFICATE")
    print()

for alias, sk in ks.secret_keys.items():
    print("Secret key: %s" % sk.alias)
    print("  Algorithm: %s" % sk.algorithm)
    print("  Key size: %d bits" % sk.key_size)
    print("  Key: %s" % "".join("{:02x}".format(b) for b in bytearray(sk.key)))
    print()
```


Transforming an encrypted JKS/JCEKS file into an OpenSSL context:
```python
import OpenSSL
import jks

_ASN1 = OpenSSL.crypto.FILETYPE_ASN1


def jksfile2context(jks_file, passphrase, key_alias, key_password=None):
    keystore = jks.KeyStore.load(jks_file, passphrase)
    pk_entry = keystore.private_keys[key_alias]
    # if the key could not be decrypted using the store password, decrypt with a custom password now
    if not pk_entry.is_decrypted():
        pk_entry.decrypt(key_password)

    pkey = OpenSSL.crypto.load_privatekey(_ASN1, pk_entry.pkey)
    public_cert = OpenSSL.crypto.load_certificate(_ASN1, pk_entry.cert_chain[0][1])
    trusted_certs = [OpenSSL.crypto.load_certificate(_ASN1, cert.cert) for alias, cert in keystore.certs]

    ctx = OpenSSL.SSL.Context(OpenSSL.SSL.TLSv1_METHOD)
    ctx.use_privatekey(pkey)
    ctx.use_certificate(public_cert)
    ctx.check_privatekey()  # want to know ASAP if there is a problem
    cert_store = ctx.get_cert_store()
    for cert in trusted_certs:
        cert_store.add_cert(cert)
    return ctx
```
