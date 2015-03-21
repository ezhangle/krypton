Krypton - Embedded TLS/DTLS library
===================================

Krypton is a drop-in replacement for OpenSSL.
Krypton is a source and binary compatible OpenSSL subset. Main design goal goal
was to minimize static and runtime memory footprint.

## Usage

Just copy a single file, `krypton.c`, to your source repo.

If you're already using OpenSSL library and wish to switch to Krypton,
just add `krypton.c` file to the build, and remove `-lssl -lcrypto` build
options:

     OpenSSL:  cc app.c -lssl -lcrypto
     Krypton:  cc app.c krypton.c

If you're not using OpenSSL and OpenSSL headers are not installed on you're
workstation, just copy over `openssl` directory to your build as well.

## Supported API

See [openssl/ssl.h](openssl/ssl.h) header file for the list of supported functions.

## Certificate Verification

1. As a simplification, full candidate certificate chains back to a self-signed
root CA are not checked. The chain will run from the server cert, through all
intermediate certs provided by the server to a single certificate in the
clients CA store, which will be used as the trust anchor.

2. Expiration dates are not checked.

3. In either case, no X509 API is provided to check the subject name, alternate
names, dns name extensions etc. belonging to the server certificate.

A possible solution for this might be to use 3rd party tools to ensure that the
clients CA store is valid and is not used outside of expiration dates.


## Performance

Apart from cryptographic primatives, which are entirely 3rd-party, there may be
several optimisations and code cleanups possible.

For example:

  - if not verifying, don't bother hashing servers cert
  - make security struct be temporary
  - assigned read/write keys/state in to main ssl struct
  - if a packet is too big for recieve buffer, peek its size for buf realloc
  - strip handshake header in handle_handshake(), would reduce code size

Probably the bigger performance improvements would be to add session ticketing
to avoid costly handshakes wherever possible.

## Renegotiation

Not supported. This wouldn't be too difficult to support:

  - server: send both finished messages in hello reneg info EXT
  - client: re-send finished message in hello reneg info EXT
  - client: respond to hello request with a new hello
  - debug with s_client renegotiation


## Implementing more secure cipher modes

RC4 is being phased out. The best bet for a new cipher that will ensure forward
compatibility is probably AES in CBC mode. This would require generating IV's
from the master secret and implementing padding and CBC. However, CBC mode may
be phased out in favour of GCM or AEAD modes. The block cipher mode
implementations are probably the most complex parts of such an upgrade.

More secure HMAC functions are pretty trivial to add. X509 already requires
SHA1 and TLS1.2 already requires SHA256. It's just a matter of wiring up the
relevant cipher spec ID's.

More secure key exchange protocols such as Diffie-Hellman with ECDSA would be
rather complex to add.

## Limitations

It supports only TLSv1.2 and only one cipher suite (RSA-RC4-MD5) in
both blocking and non-blocking socket modes.
Renegotiation, more secure cipher suites, CRL's,
OCSP stapling, session ticketing, client certificates, and other advanced
features are not supported.

The `SSL_read()` buffer must always be big enough.
If a large appdata packet is recieved and the buffer passed to SSL_read() doesn't have space for it, then some data will be discarded.

Some high bits of 3-byte length fields are ignored, which could mean we fail to
parse some messages over 64KiB in length. For example, huge certificate chains.

The code should be robust against bad message formatting. But unexpected
messages (such as renegotiations, or server requests for client certificates)
could lead to unexpected, possibly exploitable, conditions.

Some timing attacks are not worked around, but there are defences against
Bleichenbacher attacks. No key material is ever scrubbed from memory. The RC4
cipher is weak. Although the MD5 hash is weak, there are currently no known
practical attacks when it is used in the HMAC configuration.

# Contributions

People who have agreed to the
[Cesanta CLA](http://cesanta.com/contributors_la.html)
can make contributions. Note that the CLA isn't a copyright
_assigment_ but rather a copyright _license_.
You retain the copyright on your contributions.

## Licensing

Krypton is released under commercial and
[GPL v.2](http://www.gnu.org/licenses/old-licenses/gpl-2.0.html) open
source licenses. The GPLv2 open source License does not generally permit
incorporating this software into non-open source programs.
For those customers who do not wish to comply with the GPLv2 open
source license requirements,
[Cesanta](http://cesanta.com) offers a full,
royalty-free commercial license and professional support
without any of the GPL restrictions.
