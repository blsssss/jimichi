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
| Counter window | the range of cell numbers a node accepts, the replay defence |
| Memory dump | a snapshot of process memory, used in key extraction scenarios |
| ROC, AUC | the error curve and the area under it, the measure of attack success |
| Bootstrap | a resampling method for confidence intervals |
