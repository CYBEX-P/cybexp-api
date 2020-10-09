# =========== Encryption ========================

def encrypt_file(fbytes, fpub_name="pub.pem"):
    """
    Data sets sent from querys get encrypted in here. A session key is generated and encrypted
    with the public RSA key. The data is then ecrypted with the public RSA key via a
    tag and cyphertext. the encrypted session and data are returned
    
    Parameters
    ----------
    fybtes: String or list of Strings
        the data that will be encrypted
    fpub_name:String
        the public key to be used
        Default: pub.pem

    """
    
    from Crypto.PublicKey import RSA
    from Crypto.Random import get_random_bytes
    from Crypto.Cipher import AES, PKCS1_OAEP

    din = fbytes

    pubkey = RSA.import_key(open(fpub_name).read())
    session_key = get_random_bytes(32)

    # Encrypt the session key with the public RSA key
    cipher_rsa = PKCS1_OAEP.new(pubkey)
    enc_session_key = cipher_rsa.encrypt(session_key)

    # Encrypt the data with the AES session key
    cipher_aes = AES.new(session_key, AES.MODE_EAX)
    ciphertext, tag = cipher_aes.encrypt_and_digest(din)
    dout = enc_session_key + cipher_aes.nonce + tag + ciphertext
    return dout

