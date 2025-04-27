import os
import requests
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import ExtensionOID
from datetime import datetime, timezone

def get_crl_url(cert):
    """Récupère l'URL de la CRL à partir du certificat"""
    try:
        ext = cert.extensions.get_extension_for_oid(ExtensionOID.CRL_DISTRIBUTION_POINTS)
        for point in ext.value:
            if point.full_name:
                return point.full_name[0].value
    except Exception:
        pass
    return None

def download_crl(url, path):
    """Télécharge la CRL et l'enregistre"""
    resp = requests.get(url)
    if resp.status_code == 200:
        with open(path, 'wb') as f:
            f.write(resp.content)
        print(f"CRL téléchargée depuis {url}")
    else:
        raise Exception(f"Erreur de téléchargement CRL ({resp.status_code})")

def load_crl(path):
    """Charge une CRL depuis un fichier"""
    with open(path, 'rb') as f:
        crl_data = f.read()
    return x509.load_der_x509_crl(crl_data, default_backend())

def validate_crl(cert):
    """Valide un certificat contre sa CRL (cache + téléchargement)"""
    crl_url = get_crl_url(cert)
    if crl_url is None:
        print("Pas d'URL de CRL trouvée dans le certificat.")
        return False

    crl_filename = "cache_" + crl_url.split("/")[-1]
    
    if os.path.exists(crl_filename):
        crl = load_crl(crl_filename)
        now = datetime.now(timezone.utc)
        if not (crl.last_update_utc <= now <= crl.next_update_utc):
            print("CRL expirée, re-téléchargement...")
            download_crl(crl_url, crl_filename)
            crl = load_crl(crl_filename)
    else:
        print("Pas de CRL en cache, téléchargement...")
        download_crl(crl_url, crl_filename)
        crl = load_crl(crl_filename)

    # Vérification de révocation
    for revoked_cert in crl:
        if revoked_cert.serial_number == cert.serial_number:
            print("!!! Certificat révoqué !!!")
            return False
    return True
