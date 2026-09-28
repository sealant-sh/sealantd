---
"@sealant/runtime-protocol": patch
"@sealant/runtime-client": patch
---

A final flush asks about a refused seal again (review 12 #4). Only a `recorded` seal answer
outlives the final flush that heard it. A final flush over an unchanged disk that an earlier
one heard `refused` or `withheld` sends the sealing register again at once. That is one register
per final flush for a registrar that keeps refusing. A registrar that refused while it could not
read the objects, and has since recovered, now gets to record the seal. Before, the daemon kept
the first refusal, and repeated final flushes answered `sealing` without asking again.
