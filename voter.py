from Crypto.PublicKey import RSA #pycryptome
from Crypto.PublicKey.RSA import RsaKey
from Crypto.Util.number import GCD, inverse

from phe import paillier, PaillierPublicKey, PaillierPrivateKey, EncryptedNumber

import os
import random
import json

def paillier_encrypt(candidate_index: int, num_candidates: int, paillier_public_key: PaillierPublicKey) -> list[EncryptedNumber]:
    if candidate_index < 0 or candidate_index >= num_candidates:
        print("Err: vote index out of bounds")

    vote = [int(i == candidate_index) for i in range(len(candidates))]
    #encrypted_vote = [EncryptedNumber(0, 0)] * len(candidates)]
    encrypted_vote = []

    for i in range(num_candidates):
        encrypted_vote.append(paillier_public_key.encrypt(vote[i]))

    return encrypted_vote

def blind_vote(encrypted_vote: list[EncryptedNumber], rsa_public_key: RsaKey):
    # Generate a random blinding factor
    blinded_vote = [0] * len(encrypted_vote)
    r_values = [0] * len(encrypted_vote)

    for i in range(len(encrypted_vote)):
        # Get the paillier encryption int
        m = encrypted_vote[i].ciphertext()

        # Generate a random blinding factor
        r_values[i] = random.randint(1, rsa_public_key.n - 1)

        # Ensure r and n are coprime
        while GCD(r_values[i], rsa_public_key.n) != 1:
            r_values[i] = random.randint(1, rsa_public_key.n - 1)

        # Blind the message
        blinded_vote[i] = (m * pow(r_values[i], rsa_public_key.e, rsa_public_key.n)) % rsa_public_key.n

    return r_values, blinded_vote

def unblind_signature(signatures: list[int], r_values: list[int], rsa_public_key: RsaKey) -> list[int]:
    r_inv_values = [0] * len(r_values)
    unblinded_signatures = [0] * len(r_values)

    for i in range(len(signatures)):
        # Compute r^-1 mod n using the mod_inverse function
        r_inv_values[i] = inverse(r_values[i], rsa_public_key.n)

        # Unblind the signature
        unblinded_signatures[i] = (signatures[i] * r_inv_values[i]) % rsa_public_key.n

    return unblinded_signatures

if __name__ == "__main__":
    # info given from server to everyone, publically
    rsa_public_key = None
    paillier_public_key = None
    candidates = []

    with open("public/rsa.pub", "rb") as rsaf:
        rsa_public_key = RSA.importKey(rsaf.read())

    with open("public/paillier.pub", "rb") as palf:
        paillier_public_key = PaillierPublicKey(json.load(palf)['n'])

    with open("public/candidates.pub", "r") as canf:
        candidates = [candidate.strip() for candidate in canf]

    # info known by this client
    secret = input("What is the voting secret you arranged with the voting authority?\n> ")

    confirmed = False
    vote = -1
    while confirmed == False:
        print("The candidates given by the voting authority are", candidates)
        vote = int(input("Select the index of which candidate you are voting for (starting from 0)\n> "))

        print("Confirming you wish to use your voting secret", secret, "to register a vote for", candidates[vote])
        if input("Enter `yes` (lower case) to confirm.\n> ") == "yes":
            confirmed = True

    encrypted = paillier_encrypt(vote, len(candidates), paillier_public_key)

    r_values, blinded = blind_vote(encrypted, rsa_public_key)

    # save blinded vote where server can see in election/registration/input/<exisitng_entries+1>
    reg_in_path = "./election/registration/input/"
    our_number = str(len([f for f in os.listdir(reg_in_path) if os.path.isfile(os.path.join(reg_in_path, f))]))

    with open(reg_in_path+our_number, "w") as ripf:
        json.dump({'secret': secret, 'blinds': blinded}, ripf)

    command = input("Your registration has been sent to the authority. Once the registration phase ends, enter `/submit-vote`\n> ")
    while command != "/submit-vote":
        command = input("Your registration has been sent to the authority. Once the registration phase ends, enter `/submit-vote`\n> ")

    # check election/registration/output/<saved_number>/#.txt
    reg_out_path = "./election/registration/output/"

    signature = [0] * len(candidates)
    if len([f for f in os.listdir(reg_out_path) if f == our_number]) != 1:
        print("Debug - ", [f for f in os.listdir(reg_out_path)])
        print("Error - our secret was not accepted by authority")
        raise SystemExit
    else:
        with open(reg_out_path+our_number, "r") as rof:
            signature = json.load(rof)["signed_blinds"]

    unblinded_signature = unblind_signature(signature, r_values, rsa_public_key)
    # finally, send unblinded vote signature together with unblinded unsigned vote
    vote_in_path = "./election/voting/input/"
    new_number = str(len([f for f in os.listdir(vote_in_path) if os.path.isfile(os.path.join(vote_in_path, f))]))

    for i in range(len(candidates)):
        with open(vote_in_path+new_number, "w") as vipf:
            #print(dict(zip([number.ciphertext() for number in encrypted], unblinded_signature)))
            json.dump(dict(zip([str(number.ciphertext()) for number in encrypted], unblinded_signature)), vipf)

    print("Unblinded vote was sent with signature. You can view the data in ???. Once the vote ends, the voting authority will share so you can check your vote counted.")
    # TODO output the hash of each signature, to be verified with server