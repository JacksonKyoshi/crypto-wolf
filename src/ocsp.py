import requests
from cryptography.x509.ocsp import OCSPRequestBuilder, load_der_ocsp_response
from cryptography.x509.oid import ExtensionOID, AuthorityInformationAccessOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import Encoding


def get_url(cert, oid, access_method=None):
    for ext in cert.extensions:
        if ext.oid == oid:
            if oid == ExtensionOID.AUTHORITY_INFORMATION_ACCESS:
                for desc in ext.value:
                    if desc.access_method == access_method:
                        return desc.access_location.value
            elif oid == ExtensionOID.CRL_DISTRIBUTION_POINTS:
                for point in ext.value:
                    if point.full_name:
                        return point.full_name[0].value
    return None

def verify_ocsp(cert, issuer_cert):
    url = get_url(cert, ExtensionOID.AUTHORITY_INFORMATION_ACCESS, AuthorityInformationAccessOID.OCSP)
    try:
        req = OCSPRequestBuilder().add_certificate(cert, issuer_cert, hashes.SHA1()).build()
        data = req.public_bytes(Encoding.DER)
        resp = requests.post(url, data=data, headers={'Content-Type': 'application/ocsp-request'})
        if resp.status_code == 200:
            ocsp_resp = load_der_ocsp_response(resp.content)
            return {"status": ocsp_resp.certificate_status.name}
        
    except Exception as e:
        print(f"Erreur OCSP : {e}")
        return False