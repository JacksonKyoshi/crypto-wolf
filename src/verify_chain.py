from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, ec


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
