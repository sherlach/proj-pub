from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
from Crypto.Signature import pkcs1_15
from Crypto.Random import random
from Crypto.Util.number import bytes_to_long, long_to_bytes, inverse

def blind_data(message, rsakey):
    # Hash the message
    hash_obj = SHA256.new(long_to_bytes(message))
    h = bytes_to_long(hash_obj.digest())

    # Generate a random blinding factor
    r = random.StrongRandom().randint(1, rsakey.n - 1)

    # Calculate the blinded message (m_blind = m * r^e mod n)
    blind_message = (h * pow(r, rsakey.e, rsakey.n)) % rsakey.n
    return blind_message, r

def sign_blind_data(blind_message, rsakey):
    # Sign the blinded message using the private key
    blind_signature = pow(blind_message, rsakey.d, rsakey.n)
    return blind_signature

def unblind_signature(blind_signature, r, rsakey):
    # Ensure that the inverse is computed safely with large integers
    r_inv = inverse(r, rsakey.n)
    signature = (blind_signature * r_inv) % rsakey.n
    return signature

def verify_signature(signature, message, rsakey):
    # Hash the original message
    hash_obj = SHA256.new(long_to_bytes(message))
    h = bytes_to_long(hash_obj.digest())

    # Verify the signature
    signed_h = pow(signature, rsakey.e, rsakey.n)
    return h == signed_h

# Example usage:
if __name__ == "__main__":
    # Generate RSA key pair
    key = RSA.generate(2048)

    message = 1101

    # Blinding the data
    blind_message, r = blind_data(message, key)

    # Signing the blinded data
    blind_signature = sign_blind_data(blind_message, key)

    # Unblinding the signature
    signature = unblind_signature(blind_signature, r, key)

    # Verifying the signature
    is_valid = verify_signature(signature, message, key)

    print(f"Signature valid: {is_valid}")