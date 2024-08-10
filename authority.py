from phe import paillier, PaillierPublicKey, PaillierPrivateKey, EncryptedNumber
from typing import TypeAlias, Tuple

from Crypto.PublicKey import RSA #pycryptome
from Crypto.PublicKey.RSA import RsaKey

import os
import shutil

import json # for reading election.config
import logging
logger = logging.getLogger(__name__)

Secret: TypeAlias = str

class Registration:
    def __init__(self, secret: Secret, vote: list):
        self.secret = secret
        self.vote = vote

class SecretRegistry:
    def __init__(self, secrets: list[Secret]):
        self.secrets = {secret: True for secret in secrets} # make a dict mapping each secret
        print(self.secrets)

    # Check the given information
    # We will make the assumption the voting authority has made some way to distribute the voting
    # secret to each participant. This is analogous to the way real life voting works (the person on
    # the voting roll gives their address to the voting staff volunteer, who marks them off.) In this
    # implementation, the voting secret could be anything. Eg. passwords, the voter's personal information,
    # one time keys distributed before the event via a trusted channel.
    def use_secret(self, secret: Secret) -> bool:
        if self.secrets.get(secret) == True:
            self.secrets[secret] = False # do not allow repeated use of the same secret
            return True
        else: # either False or null
            print("Err: Invalid key attempted.")
            return False

def check_valid_signature(vote: list, signatures: list, rsa_public_key: RsaKey) -> bool:
    # Convert the message to an integer
    for i in range(len(vote)):
        if vote[i] != pow(signatures[i], rsa_public_key.e, rsa_public_key.n):
            print("ERR, invalid sig")
            print(vote[i])
            print(pow(signatures[i], rsa_public_key.e, rsa_public_key.n))
            return False

    return True

class SignedVotes:
    def __init__(self):
        # This is a list of (candidate_index:int, vote, signature) triples
        self.signed_votes = []

    def request_submit_vote(self, encrypted_vote: list, signatures: list, paillier_public_key: PaillierPublicKey):
        # 1. check there's a valid signature
        # 2. if so, add the EncryptedNumber to the saved votes

        if check_valid_signature(encrypted_vote, signatures, rsa_public_key):
            for i in range(len(encrypted_vote)):
                self.signed_votes.append((i, EncryptedNumber(paillier_public_key, encrypted_vote[i]), signatures[i]))

            print("DEBUGG", self.signed_votes)
        else:
            print("ERR, invalid signature sent")


    def tally_votes(self, candidates: list[str], pallier_private_key: PaillierPrivateKey) -> dict:
        candidate_votes_encrypted = {} # generated from self.signed_votes dict {candidate_index: EncryptedNumber}
        candidate_votes_decrypted = {} # dict {candidate_name: int}

###
        for entry in self.signed_votes:
            candidate_votes_encrypted[entry[0]] *= entry[1]

        for index, encrypted_tally in candidate_votes_encrypted.items():
            candidate_votes_decrypted[candidates[index]] = pallier_private_key.decrypt(encrypted_tally)
###

        #for candidate in candidates:
        #    candidate_votes_encrypted[candidate] = 1
#
#            for signed_vote in self.signed_votes:
#                candidate_votes_encrypted[candidate] *= signed_vote[0] # Paillier property of homomorphic encryption means the decryption will be the sum
#
#            candidate_votes_decrypted[candidate] = pallier_private_key.decrypt(candidate_votes_encrypted[candidate])

        # check the number of votes is correct otherwise the election is invalid
        num_voters = len(self.signed_votes) / len(candidates)
        assert sum(candidate_votes_decrypted.values()) == num_voters, "ERROR: INVALID ELECTION, WRONG NUMBER OF VOTES"

        return candidate_votes_decrypted

    def provide_confirmation(self):
        return
        # TODO hash all signatures and print such that the voter can see their hash
        # TODO jumble up the order of signatures

def clean():
    shutil.rmtree("./election")
    os.makedirs("./election/registration/input")
    os.makedirs("./election/registration/output")
    os.makedirs("./election/voting/input")

def setup(secrets: list[Secret]) -> Tuple[PaillierPublicKey, PaillierPrivateKey, RsaKey, RsaKey, SecretRegistry]:
    clean()

    paillier_public_key, paillier_private_key = paillier.generate_paillier_keypair()
    secret_registry = SecretRegistry(secrets)

    # Generate RSA keys
    rsa_private_key = RSA.generate(2048)
    rsa_public_key = rsa_private_key.publickey()

    with open("public/rsa.pub", "wb") as rsaf:
        rsaf.write(rsa_public_key.exportKey(format="PEM"))

    with open("public/paillier.pub", "w") as palf:
        json.dump({'n': paillier_public_key.n}, palf)

    print("Public keys generated and distributed to all.")

    return paillier_public_key, paillier_private_key, rsa_private_key, rsa_public_key, secret_registry

def sign(blinded_vote: list, rsa_private_key: RsaKey):
    signatures = []

    for i in range(len(blinded_vote)):
        # Sign the blinded message
        signatures.append(pow(blinded_vote[i], rsa_private_key.d, rsa_private_key.n))

    return signatures

# if a valid secret is given, sign the hash of the blinded message?
def request_signature(vote: Registration, secret_registry: SecretRegistry, rsa_private_key: RsaKey):
    if secret_registry.use_secret(vote.secret): # successfully used a secret
        return sign(vote.vote, rsa_private_key)

if __name__ == "__main__":
    debug = True
    logging.basicConfig()

    candidates = []
    secrets = []

    with open("election-config.json") as json_file:
        json_data = json.load(json_file)
        candidates = json_data["candidates"]
        secrets = json_data["secrets"]

    with open("public/candidates.pub", "w") as wcf:
        for candidate in candidates:
            wcf.write(f"{candidate}\n")
        print("Candidates list made publically available to voters.")

    paillier_public_key, paillier_private_key, rsa_private_key, rsa_public_key, secret_registry = setup(secrets)

    #print(paillier_public_key, rsa_public_key) # all voters can access

    logger.info("SPC")
    command = input("Setup Phase complete. Registration now open. Type `/end-reg` to end registration phase.\n> ")
    while command != "/end-reg":
        command = input("Setup Phase complete. Registration now open. Type `/end-reg` to end registration phase.\n> ")

    # REGISTRATION PHASE

    # sign the blinded, encrypted vote and give it to the voter
    reg_in_path = "./election/registration/input/"
    registration_requests = [f for f in os.listdir(reg_in_path) if os.path.isfile(os.path.join(reg_in_path, f))]

    reg_out_path = "./election/registration/output/"

    for vote_registration in registration_requests:
        with open(reg_in_path + vote_registration, "rb") as rrif:
            registration = json.load(rrif)
            registration = Registration(registration["secret"], registration["blinds"])
            vote_signature = request_signature(registration, secret_registry, rsa_private_key)

            if vote_signature != None:
                with open(reg_out_path+vote_registration, "w") as roof:
                    json.dump({'signed_blinds': vote_signature}, roof)
            else:
                print("Err: Invalid registration request")

    logger.info("RPC")
    command = input("Registration Phase complete. Voters may now submit their votes. Type `/end-vote` to end voting phase.\n> ")
    while command != "/end-vote":
        command = input("Registration Phase complete. Voters may now submit their votes. Type `/end-vote` to end voting phase.\n> ")

    signed_votes = SignedVotes()
    ## now the voters have submitted their encrypted, unblinded vote and signature anonymously

    vote_in_path = "./election/voting/input/"
    vote_requests = [f for f in os.listdir(vote_in_path) if os.path.isfile(os.path.join(vote_in_path, f))]

    for signed_vote in vote_requests:
        with open(vote_in_path + signed_vote, "r") as vif:
            vote = json.load(vif)
            signed_votes.request_submit_vote(list(vote.keys()), list(vote.values()), paillier_public_key)

    # if !debug, we should wipe election/registration/output/*
    if not debug:
        clean()

    print(signed_votes.tally_votes(candidates, paillier_private_key))

    # TODO finally, for verification purposes, we display a hash of every signature
    print(signed_votes.provide_confirmation())