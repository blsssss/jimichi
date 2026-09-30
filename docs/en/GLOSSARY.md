# Glossary

English | [Русский](../ru/GLOSSARY.md)

| Term | Meaning |
|---|---|
| Cell | the unit of transmission, constant 512 bytes |
| Layer | one level of encryption, stripped by one node of the chain |
| Hop | a step between neighbouring nodes of the chain |
| Circuit | the three nodes a message travels through, chosen by the client |
| Ephemeral key | a key that lives for one session and is zeroed afterwards |
| UKM | the value binding an agreed secret to a session |
| AEAD | authenticated encryption with associated data |
| Cover traffic | cells with no payload that hide when a real message is sent |
| Link padding | a frame a node sends to its neighbour on an empty tick of its schedule; the neighbour drops it |
| Own-clock sending | a node sends one cell per tick of its own timer, not at the moment the cell arrives |
| Padding | bytes added to reach the constant cell size |
| Correlation attack | linking sender and recipient by timings and volumes |
| Unlinkability | the property that an observer cannot link sender and recipient |
| Forward secrecy | compromise of a long-term key does not expose past sessions |
| Trust anchor | the CA public key the client trusts in advance, as the string `<suite>:<base64>` |
| Node certificate | a CA-signed record binding a node's name, address and signing key for a validity period |
| Node signing key | the node's long-term signing pair (identity key): it signs the certificate request and the descriptor and takes no part in key agreement |
| Onion key | the node key the client agrees a layer secret with during circuit setup |
| Link key | the node public key (LinkPub in the descriptor) the client mixes into the link handshake with the entry node |
| Node descriptor | a record signed by the node signing key: certificate hash, link key, onion key, epoch and a short validity |
| Epoch | the number of the link and onion key set in a descriptor: it counts the node's changes of those keys, 0 for the first set |
| Node bundle | the node certificate and descriptor in one JSON object, which the node serves to clients |
| Operator roster | the list of node names and addresses the operator allows certificates for |
| Certificate issuance | the CA checks a node's signed request, carrying a nonce the CA chose, against the operator roster and signs the certificate |
| Counter order | on every link a node accepts only the counter one above the previous one, anything else closes the circuit; the replay defence |
| Memory dump | a snapshot of process memory, used in key extraction scenarios |
| ROC, AUC | the error curve and the area under it, the measure of attack success |
| Bootstrap | a resampling method for confidence intervals |
