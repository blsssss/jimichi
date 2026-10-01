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
| Onion key | the node key the client agrees a layer secret with during circuit setup; with rotation a node replaces it by epochs |
| Link key | the node public key (LinkPub in the descriptor) the initiator of a link to that node mixes into the handshake: the client for its entry, a node for the next node of a circuit |
| Node descriptor | a record signed by the node signing key: certificate hash, link key, onion key, epoch and a short validity |
| Onion key epoch | the number of the node's onion key in its descriptor: 0 for the first key of a process, one more after every rotation; the link key does not change with it |
| Grace period | the time a node still holds a replaced onion key: the descriptor lifetime plus the clock allowance after the rotation |
| Node bundle | the node certificate and descriptor in one JSON object, which the node serves to clients |
| Operator roster | the list of node names and addresses the operator allows certificates for |
| Node roster | the anchor with the names and addresses of the nodes of one issuance, sent to each of them; a node extends circuits only to roster nodes |
| Descriptor mirror | the bundles of all roster nodes, which a node serves on /descriptors so that a client asks its entry alone |
| Certificate issuance | the CA checks a node's signed request, carrying a nonce the CA chose, against the operator roster and signs the certificate |
| Counter order | on every link a node accepts only the counter one above the previous one, anything else closes the circuit; the replay defence |
| Memory dump | a snapshot of process memory, used in key extraction scenarios |
| ROC, AUC | the error curve and the area under it, the measure of attack success |
| Bootstrap | a resampling method for confidence intervals |
