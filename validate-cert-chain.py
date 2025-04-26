from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
import sys
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.primitives.hashes import Hash
from ecpy.curves import Curve, Point
from cryptography.x509.oid import ExtensionOID

def loadCertificate(cert_path,cert_format):
    ###fonction pour lire un certificat en fonction de son format###
    with open(cert_path,'rb') as cert_info:
        cert_data = cert_info.read()
    if cert_format == "PEM":
        cert = x509.load_pem_x509_certificate(cert_data)
    elif cert_format == "DER":
        cert = x509.load_der_x509_certificate(cert_data)
    else:
        print("wrong format")
    return cert



def verify_chain_certificat(certs):
    for i in range(len(certs) - 1):
        issuer_cert = certs[i]
        subject_cert = certs[i + 1]

        if issuer_cert.subject != subject_cert.issuer:
            print(f"Erreur : Le sujet de {i+1} ne correspond pas à l'émetteur de {i}")
            return False

        public_key = issuer_cert.public_key()

        try:
            if isinstance(public_key, rsa.RSAPublicKey):
                public_key.verify(
                    subject_cert.signature,
                    subject_cert.tbs_certificate_bytes,
                    padding.PKCS1v15(),
                    subject_cert.signature_hash_algorithm,
                )
            elif isinstance(public_key, ec.EllipticCurvePublicKey):
                public_key.verify(
                    subject_cert.signature,
                    subject_cert.tbs_certificate_bytes,
                    ec.ECDSA(subject_cert.signature_hash_algorithm),
                )
            else:
                print(f"Type de clé non supporté pour {i}")
                return False

            print(f"Signature de certificat {i+1} vérifiée")
        
        except Exception as e:
            print(f"Erreur de vérification de la signature entre {i} et {i+1}: {e}")
            return False

    # Vérification du certificat racine
    try:
        root_cert = certs[0]
        root_public_key = root_cert.public_key()

        if isinstance(root_public_key, rsa.RSAPublicKey):
            root_public_key.verify(
                root_cert.signature,
                root_cert.tbs_certificate_bytes,
                padding.PKCS1v15(),
                root_cert.signature_hash_algorithm,
            )
        elif isinstance(root_public_key, ec.EllipticCurvePublicKey):
            root_public_key.verify(
                root_cert.signature,
                root_cert.tbs_certificate_bytes,
                ec.ECDSA(root_cert.signature_hash_algorithm),
            )
        else:
            print("Type de clé non supporté pour le certificat racine")
            return False

        print("Certificat racine autosigné vérifié !")

    except Exception as e:
        print(f"Erreur de vérification du certificat racine : {e}")
        return False

    return True

def bytes_to_long(byte_array):
    return int.from_bytes(byte_array, byteorder='big')

def long_to_bytes(n):
    length = (n.bit_length() + 7) // 8  # nombre de bytes nécessaires
    return n.to_bytes(length, byteorder='big')


def verifiy_signature(mode,issuer_public_key, cert):
    hash_algorithm = cert.signature_hash_algorithm
    message = cert.tbs_certificate_bytes
    signature = cert.signature
    # Calculate the hash of the message
    hash_obj = Hash(hash_algorithm)
    hash_obj.update(message)
    message_hash = bytes_to_long(hash_obj.finalize())

    if mode == "RSA":
        # Extract RSA public key parameters
        e, n = issuer_public_key.public_numbers().e, issuer_public_key.public_numbers().n
        s = bytes_to_long(signature)

        # SHA-256 ASN.1 header used in RSA PKCS#1v1.5 signatures
        sha256_header = bytes.fromhex("3031300d060960864801650304020105000420")

        # Verify the signature using RSA
        signature_to_verify = long_to_bytes(pow(s, e, n))
        message_to_verify = long_to_bytes(message_hash % n)

        # Find the padding boundary and extract the actual signature
        start_of_signature = signature_to_verify.find(b"\x00", 1)
        signature_to_verify = signature_to_verify[start_of_signature + 1:]

        return signature_to_verify == sha256_header + message_to_verify
    else:  # ECDSA
        # Get curve parameters
        curve = Curve.get_curve(issuer_public_key.public_numbers().curve.name)
        n = curve.order
        G = curve.generator

        # Create a point from the public key coordinates
        Qa = Point(issuer_public_key.public_numbers().x, issuer_public_key.public_numbers().y, curve)

        # Decode the DER-encoded signature
        decoded_signature = decode_der_signature(signature)
        if decoded_signature is None:
            print("Malformed signature")
            return False
        r, s = decoded_signature

        # Perform ECDSA signature validation checks
        if not curve.is_on_curve(Qa):
            print("Wrong public key")
            return False
        if not 1 < r < (n - 1):
            print("Wrong signature")
            return False
        if not 1 < s < (n - 1):
            print("Wrong signature")
            return False

        # Calculate signature verification values
        u = modular_inverse(s, n)
        u1 = (message_hash * u) % n
        u2 = (r * u) % n

        # Perform the ECDSA verification calculation
        P = u1 * G + u2 * Qa
        r1 = P.x % n

        return r1 == r

def decode_der_signature(sequence):
    # Verify this is a sequence
    if sequence[0] != 0x30:
        return None

    sequence_length = sequence[1]

    # Parse the r component
    r_sequence = sequence[2:]
    if r_sequence[0] != 0x02:  # r should be an integer
        return None

    r_integer_length = r_sequence[1]
    r = bytes_to_long(r_sequence[2:r_integer_length + 2])

    # Parse the s component
    s_sequence = r_sequence[r_integer_length + 2:]
    if s_sequence[0] != 0x02:  # s should be an integer
        return None

    s_integer_length = s_sequence[1]
    s = bytes_to_long(s_sequence[2:s_integer_length + 2])

    return r, s
    
    
    
def modular_inverse(a, n):
    # Algorithme d'Euclide étendu pour trouver l'inverse
    t, new_t = 0, 1
    r, new_r = n, a
    
    while new_r != 0:
        quotient = r // new_r
        
        # Mise à jour des valeurs de t et r
        t, new_t = new_t, t - quotient * new_t
        r, new_r = new_r, r - quotient * new_r
    
    if r > 1:
        # a et n ne sont pas premiers entre eux, pas d'inverse
        return None
    
    if t < 0:
        # Assurer que l'inverse est positif
        t = t + n
    
    return t

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

    print("basic constraint valide")
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
    print("key usage valide !")
    return True

def is_ca(cert):
    try:
        basic_constraints = cert.extensions.get_extension_for_oid(ExtensionOID.BASIC_CONSTRAINTS).value
        return basic_constraints.ca
    except Exception:
        # Pas d'extension BasicConstraints => considéré comme PAS un CA
        return False



if __name__ == "__main__":
    cert_format = sys.argv[2].upper()  # Récupération du format
    cert_paths = sys.argv[3:]           # Tous les chemins restants

    print(f"Format des certificats : {cert_format}")
    print(f"Fichiers de certificats : {cert_paths}")

    certs = []  # Liste pour stocker les certificats

    for cert_path in cert_paths:
        cert = loadCertificate(cert_path, cert_format)
        certs.append(cert)

    # À ce stade, 'certs' contient tous tes certificats chargés
    print(f"{len(certs)} certificats chargés avec succès.")
    
    #vérification en chaine des certificat
    verify_chain_certificat(certs)

   #verification à la mano
    for i in range(len(certs) - 1):
       issuer_cert = certs[i]
       subject_cert = certs[i + 1]
       issuer_public_key = issuer_cert.public_key()

       if isinstance(issuer_public_key, rsa.RSAPublicKey):
           result = verifiy_signature('RSA', issuer_public_key, subject_cert)
       else:
            result = verifiy_signature('ECDSA', issuer_public_key, subject_cert)

       if result:
           print(f"Certificat {i+1} signature valide")
       else:
           print(f"Certificat {i+1} signature invalide")
    
    # Vérification du root cert
    root_cert = certs[0]
    root_public_key = root_cert.public_key()
    if isinstance(root_public_key, rsa.RSAPublicKey):
        result = verifiy_signature('RSA', root_public_key, root_cert)
    else:
        result = verifiy_signature('ECDSA', root_public_key, root_cert)

    if result:
        print("Certificat racine autosigné valide")
    else:
        print("Certificat racine autosigné invalide")
    
    for cert in certs:
        ca = is_ca(cert)
        if not check_key_usage(cert, ca):
            print("KeyUsage pas correcte pour ce certificat")

    
    for i, cert in enumerate(certs):
        if i < len(certs) - 1:  # Tous sauf le dernier
            if not verify_basic_constraints(cert, is_ca_expected=True):
                print(f"Certificat {i} : BasicConstraints invalide pour un CA")
        else:  # Dernier certificat
            if not verify_basic_constraints(cert, is_ca_expected=False):
                print(f"Certificat {i} : BasicConstraints invalide pour un certificat utilisateur")
