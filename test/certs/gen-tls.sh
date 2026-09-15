#!/bin/sh
# gen-tls.sh — a CA and a server cert for the grappa leg.
#
# bicchierino speaks HTTPS to grappa and nothing else: GRAPPA_URL_PREFIX is
# "https://" and parse_grappa_url refuses anything that does not start with
# it. It also verifies properly — SSL_VERIFY_PEER plus
# SSL_CTX_set_default_verify_paths, with the hostname checked — and that
# verification is never skipped, by design.
#
# So a test stack cannot just point it at grappa's plain :4000. It needs
# real TLS with a chain that verifies. Rather than weaken the client (which
# would mean testing something other than the shipped binary), this mints a
# throwaway CA, signs a cert for the name bicchierino will dial, and the
# bicchierino image installs the CA into its system trust store — the store
# set_default_verify_paths already reads.
#
# Self-signed and 1-day-lived on purpose: these never leave the sealed
# stack, and a short life makes it obvious if one is ever found elsewhere.
set -eu
cd "$(dirname "$0")"

# Idempotent: `up` runs this every time, and regenerating would invalidate
# a CA the bicchierino image has already baked in.
if [ -s ca.pem ] && [ -s grappa-tls.pem ]; then
    echo "gen-tls: certs already present, leaving them alone"
    exit 0
fi

echo "gen-tls: minting a throwaway CA"
openssl req -x509 -newkey rsa:2048 -nodes -days 1 \
    -subj "/CN=bicchierino test CA" \
    -keyout ca.key -out ca.pem >/dev/null 2>&1

echo "gen-tls: signing a cert for grappa-tls"
openssl req -newkey rsa:2048 -nodes \
    -subj "/CN=grappa-tls" \
    -keyout grappa-tls.key -out grappa-tls.csr >/dev/null 2>&1

# subjectAltName, not just CN: OpenSSL's X509_check_host — which is what
# bicchierino's hostname verification ends up calling — ignores CN entirely
# when a SAN is present, and modern OpenSSL will not match on CN alone.
cat > san.cnf <<'CNF'
subjectAltName = DNS:grappa-tls
extendedKeyUsage = serverAuth
CNF

openssl x509 -req -in grappa-tls.csr -CA ca.pem -CAkey ca.key \
    -CAcreateserial -days 1 -extfile san.cnf \
    -out grappa-tls.pem >/dev/null 2>&1

rm -f grappa-tls.csr san.cnf
chmod 644 ca.pem grappa-tls.pem
chmod 644 grappa-tls.key   # nginx runs unprivileged in this stack

echo "gen-tls: done"
openssl x509 -in grappa-tls.pem -noout -subject -ext subjectAltName 2>/dev/null || true
