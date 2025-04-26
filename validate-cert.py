from cryptography import x509
from cryptography.x509.oid import ExtensionOID
from cryptography.hazmat.primitives.asymmetric import padding, ec
import sys
from datetime import datetime

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

def verify_self_sign_certificate(cert):
    ###fonction pour vérifier la signature du certificat###
    try:
        if cert.verify_directly_issued_by(cert):
            print("Certificate is self-signed")
            return True
        else:
            print("Certificate is not self-signed")
            return False
    except ValueError as e:
        print(f"Certificate is not self-signed: {e}")
        return False

def verify_key_usage(cert):
    try:
        key_usage = cert.extensions.get_extension_for_oid(ExtensionOID.KEY_USAGE).value
        print("\nExtension KeyUsage :")
        print(f"- Certificate Sign : {key_usage.key_cert_sign}")
        print(f"- CRL Sign : {key_usage.crl_sign}")
        if(key_usage.crl_sign & key_usage.key_cert_sign):
            return True
        else:
            print("Pas les bonnes key_usages pour le certificat racine")
            return False
    except x509.ExtensionNotFound:
            print("L'extension KeyUsage n'est pas présente dans ce certificat.")

def certificate_validity(cert):
    # Create a timezone-aware datetime object in UTC
    from datetime import datetime, timezone
    now = datetime.now(timezone.utc)
    
    if now < cert.not_valid_before_utc:
        print("certificat pas encore valide")
    elif cert.not_valid_before_utc < now < cert.not_valid_after_utc:
        print("certificat valide !")
    elif cert.not_valid_after_utc < now:
        print("certificat expiré")


def extract_and_verify_signature(cert):
    public_key = cert.public_key()
    signature_algorithm = cert.signature_algorithm_oid._name
    signature = cert.signature
    tbs_data = cert.tbs_certificate_bytes

    print(f"Algorithme de signature : {signature_algorithm}")

    try:
        # Vérification selon le type d'algo
        if "rsa" in signature_algorithm.lower():
            public_key.verify(
                signature,
                tbs_data,
                padding.PKCS1v15(),  # pour RSA classique
                cert.signature_hash_algorithm,
            )
        elif "ecdsa" in signature_algorithm.lower():
            public_key.verify(
                signature,
                tbs_data,
                ec.ECDSA(cert.signature_hash_algorithm),
            )
        else:
            print("Erreur : Algorithme non supporté pour la vérification")
            return False

        print("✅ Signature du certificat vérifiée avec succès")
        return True
    except Exception as e:
        print(f"❌ Erreur lors de la vérification de la signature : {e}")
        return False



if __name__ == "__main__":
    cert_format = sys.argv[2].upper() #récupération du format
    cert_path= sys.argv[3] #récupération du chemin
    print(cert_format)
    print(cert_path)
    cert = loadCertificate(cert_path,cert_format)
    verify_self_sign_certificate(cert)
    
    #affichage du sujet et de l'emeteur du certificat
    print(cert.subject)
    print(cert.issuer)
    
    #verification du key_usage du certificat racine
    verify_key_usage(cert)
    
    #test de validité du certificat
    certificate_validity(cert)
    
    #test de la signature
    extract_and_verify_signature(cert)