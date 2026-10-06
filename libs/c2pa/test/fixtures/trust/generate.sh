#!/usr/bin/env bash
# Regenerates pki.pem, the mini-PKI used by the trust tests. Each PEM block is
# preceded by a "# <name>" line. Run from any directory:
#   bash libs/c2pa/test/fixtures/trust/generate.sh
set -euo pipefail

OUT="$(cd "$(dirname "$0")" && pwd)"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

VALID_FROM=20250101000000Z
VALID_TO=20991231235959Z
EXPIRED_FROM=20200101000000Z
EXPIRED_TO=20210101000000Z

cat > "$WORK/ca.cnf" <<'EOF'
[ ca ]
default_ca = test_ca

[ test_ca ]
dir = WORKDIR
database = $dir/index.txt
serial = $dir/serial
new_certs_dir = $dir/newcerts
policy = policy_any
unique_subject = no
copy_extensions = none
email_in_dn = no

[ policy_any ]
commonName = supplied

[ req ]
distinguished_name = req_dn
prompt = no

[ req_dn ]
CN = placeholder

[ root ]
basicConstraints = critical, CA:TRUE
keyUsage = critical, keyCertSign, cRLSign
subjectKeyIdentifier = hash

[ intermediate ]
basicConstraints = critical, CA:TRUE, pathlen:0
keyUsage = critical, keyCertSign, cRLSign
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid

[ intermediate_no_ca ]
basicConstraints = critical, CA:FALSE
keyUsage = critical, keyCertSign, digitalSignature
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid

[ leaf ]
basicConstraints = critical, CA:FALSE
keyUsage = critical, digitalSignature
extendedKeyUsage = 1.3.6.1.5.5.7.3.36
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid

[ leaf_claim_signing ]
basicConstraints = critical, CA:FALSE
keyUsage = critical, digitalSignature
extendedKeyUsage = 1.3.6.1.4.1.62558.2.1
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid

[ leaf_no_eku ]
basicConstraints = critical, CA:FALSE
keyUsage = critical, digitalSignature
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid

[ leaf_any_eku ]
basicConstraints = critical, CA:FALSE
keyUsage = critical, digitalSignature
extendedKeyUsage = 1.3.6.1.5.5.7.3.36, 2.5.29.37.0
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid

[ self_signed_leaf ]
basicConstraints = critical, CA:FALSE
keyUsage = critical, digitalSignature
extendedKeyUsage = 1.3.6.1.5.5.7.3.36
subjectKeyIdentifier = hash

[ leaf_ca ]
basicConstraints = critical, CA:TRUE
keyUsage = critical, digitalSignature, keyCertSign
extendedKeyUsage = 1.3.6.1.5.5.7.3.36
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid

[ leaf_no_digital_signature ]
basicConstraints = critical, CA:FALSE
keyUsage = critical, nonRepudiation
extendedKeyUsage = 1.3.6.1.5.5.7.3.36
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid

[ leaf_no_key_usage ]
basicConstraints = critical, CA:FALSE
extendedKeyUsage = 1.3.6.1.5.5.7.3.36
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid

[ leaf_time_stamping ]
basicConstraints = critical, CA:FALSE
keyUsage = critical, digitalSignature
extendedKeyUsage = 1.3.6.1.5.5.7.3.36, timeStamping
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid

[ leaf_unknown_critical ]
basicConstraints = critical, CA:FALSE
keyUsage = critical, digitalSignature
extendedKeyUsage = 1.3.6.1.5.5.7.3.36
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid
1.3.6.1.4.1.99999.1 = critical, DER:05:00

[ leaf_no_aki ]
basicConstraints = critical, CA:FALSE
keyUsage = critical, digitalSignature
extendedKeyUsage = 1.3.6.1.5.5.7.3.36
subjectKeyIdentifier = hash
authorityKeyIdentifier = none
EOF
sed -i "s|WORKDIR|$WORK|" "$WORK/ca.cnf"
mkdir -p "$WORK/newcerts"
touch "$WORK/index.txt"
echo 1000 > "$WORK/serial"

key() {
	local name=$1 alg=$2
	case "$alg" in
		ec) openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$WORK/$name.key" 2> /dev/null ;;
		secp256k1) openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:secp256k1 -out "$WORK/$name.key" 2> /dev/null ;;
		rsa1024) openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:1024 -out "$WORK/$name.key" 2> /dev/null ;;
		rsa) openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$WORK/$name.key" 2> /dev/null ;;
		pss) openssl genpkey -algorithm RSA-PSS -pkeyopt rsa_keygen_bits:2048 -out "$WORK/$name.key" 2> /dev/null ;;
		ed25519) openssl genpkey -algorithm ED25519 -out "$WORK/$name.key" ;;
	esac
}

sign_opts() {
	case "$1" in
		ec | rsa) echo "-md sha256" ;;
		pss) echo "-md sha256 -sigopt rsa_padding_mode:pss -sigopt rsa_pss_saltlen:32" ;;
		ed25519) echo "" ;;
	esac
}

# issue <name> <alg> <extensions> <issuer|self> <issuer alg> <from> <to> [subject name]
issue() {
	local name=$1 alg=$2 ext=$3 issuer=$4 issuer_alg=$5 from=$6 to=$7 subject=${8:-$1}
	key "$name" "$alg"
	openssl req -new -config "$WORK/ca.cnf" -key "$WORK/$name.key" -subj "/CN=CML Trust Test $subject" -out "$WORK/$name.csr" 2> /dev/null
	local issuer_args
	if [ "$issuer" = self ]; then
		issuer_args="-selfsign -keyfile $WORK/$name.key"
	else
		issuer_args="-cert $WORK/$issuer.pem -keyfile $WORK/$issuer.key"
	fi
	# shellcheck disable=SC2046,SC2086
	openssl ca -batch -notext -config "$WORK/ca.cnf" $issuer_args $(sign_opts "$issuer_alg") \
		-extensions "$ext" -startdate "$from" -enddate "$to" \
		-in "$WORK/$name.csr" -out "$WORK/$name.pem" 2> /dev/null
}

# EC P-256: root -> intermediate -> leaves
issue root-ec ec root self ec $VALID_FROM $VALID_TO
issue intermediate-ec ec intermediate root-ec ec $VALID_FROM $VALID_TO
issue leaf-ec ec leaf intermediate-ec ec $VALID_FROM $VALID_TO
issue leaf-ec-claim-signing ec leaf_claim_signing intermediate-ec ec $VALID_FROM $VALID_TO
issue leaf-ec-no-eku ec leaf_no_eku intermediate-ec ec $VALID_FROM $VALID_TO
issue leaf-ec-any-eku ec leaf_any_eku intermediate-ec ec $VALID_FROM $VALID_TO
issue leaf-ec-expired ec leaf intermediate-ec ec $EXPIRED_FROM $EXPIRED_TO
issue intermediate-ec-expired ec intermediate root-ec ec $EXPIRED_FROM $EXPIRED_TO
issue leaf-under-expired-intermediate ec leaf intermediate-ec-expired ec $VALID_FROM $VALID_TO
issue intermediate-ec-no-ca ec intermediate_no_ca root-ec ec $VALID_FROM $VALID_TO
issue leaf-under-no-ca-intermediate ec leaf intermediate-ec-no-ca ec $VALID_FROM $VALID_TO
issue self-signed-leaf ec self_signed_leaf self ec $VALID_FROM $VALID_TO

# Leaves that break the certificate profile of C2PA 2.4 §14.5.1.1
issue leaf-ec-ca ec leaf_ca intermediate-ec ec $VALID_FROM $VALID_TO
issue leaf-ec-no-digital-signature ec leaf_no_digital_signature intermediate-ec ec $VALID_FROM $VALID_TO
issue leaf-ec-no-key-usage ec leaf_no_key_usage intermediate-ec ec $VALID_FROM $VALID_TO
issue leaf-ec-time-stamping ec leaf_time_stamping intermediate-ec ec $VALID_FROM $VALID_TO
issue leaf-ec-unknown-critical ec leaf_unknown_critical intermediate-ec ec $VALID_FROM $VALID_TO
issue leaf-ec-no-aki ec leaf_no_aki intermediate-ec ec $VALID_FROM $VALID_TO
issue leaf-secp256k1 secp256k1 leaf intermediate-ec ec $VALID_FROM $VALID_TO

# Path length: intermediate-ec has pathlen:0, so it cannot issue another CA
issue sub-intermediate-ec ec intermediate intermediate-ec ec $VALID_FROM $VALID_TO
issue leaf-under-sub-intermediate ec leaf sub-intermediate-ec ec $VALID_FROM $VALID_TO

# Impostor: same subject name as intermediate-ec, different key
issue impostor-intermediate-ec ec intermediate self ec $VALID_FROM $VALID_TO intermediate-ec
issue leaf-ec-forged ec leaf impostor-intermediate-ec ec $VALID_FROM $VALID_TO

# Other signature algorithm families: root -> leaf
issue root-rsa rsa root self rsa $VALID_FROM $VALID_TO
issue leaf-rsa rsa leaf root-rsa rsa $VALID_FROM $VALID_TO
issue leaf-rsa-1024 rsa1024 leaf root-rsa rsa $VALID_FROM $VALID_TO
issue root-pss pss root self pss $VALID_FROM $VALID_TO
issue leaf-pss pss leaf root-pss pss $VALID_FROM $VALID_TO
issue root-ed25519 ed25519 root self ed25519 $VALID_FROM $VALID_TO
issue leaf-ed25519 ed25519 leaf root-ed25519 ed25519 $VALID_FROM $VALID_TO

CERTS="root-ec intermediate-ec leaf-ec leaf-ec-claim-signing leaf-ec-no-eku leaf-ec-any-eku leaf-ec-expired
	intermediate-ec-expired leaf-under-expired-intermediate intermediate-ec-no-ca leaf-under-no-ca-intermediate
	self-signed-leaf leaf-ec-forged root-rsa leaf-rsa root-pss leaf-pss root-ed25519 leaf-ed25519
	leaf-ec-ca leaf-ec-no-digital-signature leaf-ec-no-key-usage leaf-ec-time-stamping leaf-ec-unknown-critical
	leaf-ec-no-aki leaf-secp256k1 leaf-rsa-1024 sub-intermediate-ec leaf-under-sub-intermediate"

{
	for name in $CERTS; do
		echo "# $name"
		cat "$WORK/$name.pem"
	done
	# PKCS#8 key of leaf-ec, for tests that sign manifests
	echo "# leaf-ec.key"
	openssl pkcs8 -topk8 -nocrypt -in "$WORK/leaf-ec.key"
} > "$OUT/pki.pem"
