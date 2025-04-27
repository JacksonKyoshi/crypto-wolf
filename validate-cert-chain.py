from cryptography import x509
import sys


from src.crypto import *
from src.key_usage import *
from src.ocsp import *
from src.verify_chain import *
from src.crl import *

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
                
                
    test = []
    for i in range(len(certs)):
        if i!=0:
            test.append(validate_crl(certs[i]))
    if False in test:
        print("Test de la crl invalide")
    else:
        print("Test de la crl réussi avec succes")

    
    test = []
    for i in range(len(certs)-1):
        test.append(verify_ocsp(certs[i+1],certs[i]))
    if False in test:
        print("Test de L'Ocsp invalide")
    else:
        print("Test de l'ocsp réussi avec succes")
