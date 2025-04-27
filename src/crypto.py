from cryptography.hazmat.primitives.hashes import Hash
from ecpy.curves import Curve, Point



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