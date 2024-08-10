voting occurs in 4 phases

- setup phase: secrets are decided and distributed to respective voters, candidates are chosen, pubkeys are generated and sent. in real world this would be ??, for this
    application, pubkeys and candidates are in a file named ?? and secrets are in election.config
- registration phase: voters can get their blind vote signed and save it. in a real world application this would be saved in each voter's individual device. for this
    application, each unique new vote+sig block will be stored in a new text file in the /votes directory. IN REAL LIFE this would be stored on the voter's individual device.
- vote phase: voters can send their encrypted not blind vote along with their corresponding signature
- post phase: votes are summed by auth


first, run authoriser.py - it will save public keys to local files (in a real-world application we would publically broadcast it to all interested voters)
importantly, leave authoriser.py running!

then run voter.py as many times as you want, filling in the prompted details as if you are a voter

we simulate a command to "end the voting period" by entering <??> into the authoriser. in a real world application this could be done with a command or even
set to a certain time interval

the authoriser should then output the results

when auth is run, setup phase will automatically start. once it's time for the registration phase to end, use the /end-registration command, which will go through all
saved requests and return them
similarly there will be a /end-vote command
and finally /end-election

election.config will contain the list of candidates and secrets - in a real world application this would obviously be secret and stored with the authoriser,
not accessible to outsiders

election/registration/input
- each individual voter writes <number>.json, containing
```{

secret: "",
blinds: ["", "", "", ...]

}```
- this is read by auth

election/registration/output
- auth writes <number>.json, containing
```{

signed_blinds: ["", "", "", ...]

}```
- each voter views their own signed_blind

election/voting/input
- voter writes <new_number>.json, containing
```{
vote: {"unblinded vote": "signature", "unblinded vote": "signature",...}

}
```

TODO - doc - write about a setup where public folder is accessible by anyone, auth folder is accessible only by root, voter would be instanced separately (pretend on different devices)
    eg. send-auth could be writeable but not readable
TODO - doc - remember voting secrets set in election-config need to be secure - eg. a hash of someone's full name+birthday+address+password how many digits necessary

TODO - code - refactor blind signature code to match the experiment done in try-blind.py