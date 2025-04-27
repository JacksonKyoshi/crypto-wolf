from cryptography.x509.oid import ExtensionOID

def verify_basic_constraints(cert, is_ca_expected):
    from cryptography.x509.oid import ExtensionOID

    try:
        ext = cert.extensions.get_extension_for_oid(ExtensionOID.BASIC_CONSTRAINTS)
        basic_constraints = ext.value
    except Exception:
        print("Pas d'extension BasicConstraints")
        return False

    if basic_constraints.ca != is_ca_expected:
        print(f"Erreur : basicConstraints.ca est {basic_constraints.ca} mais on attendait {is_ca_expected}")
        return False
    return True



def check_key_usage(cert, is_ca):
    try:
        key_usage = cert.extensions.get_extension_for_oid(ExtensionOID.KEY_USAGE).value
    except Exception:
        print("Pas d'extension KeyUsage trouvée")
        return False

    if is_ca:
        if not key_usage.key_cert_sign:
            print("Erreur : CA sans droit de signer des certificats (keyCertSign=False)")
            return False
    else:
        if not (key_usage.digital_signature or key_usage.key_encipherment):
            print("Erreur : certificat utilisateur sans droit digital_signature ou key_encipherment")
            return False
    return True

def is_ca(cert):
    try:
        basic_constraints = cert.extensions.get_extension_for_oid(ExtensionOID.BASIC_CONSTRAINTS).value
        return basic_constraints.ca
    except Exception:
        # Pas d'extension BasicConstraints => considéré comme PAS un CA
        return False