# sysyguard

## a light wight real-time file scaning tool made using clamav <br>

### basic idea:
 * this is a real-time light wight file scanning tool made to use clamav as its backend. it sleeps in the background til it detects a installation of file, when detected it will auto start a file scan to see if it has virus. if found to be true it will quarantine the file in a separated encrypted file and notify the user and if shown to be false it will notify the user that it is safe to use 

### bullet point var:

* sleeps in the background till a installation is detected
* when detected it will run the clamav 
* if true it will quarantine the file and notify user
* if shown false it will notify user of safe and read to use
* then it goes back to a rest state
---
### lang:
 - i was thinking of writing this in go
 - but first i will do it in python since i am fimiller with the language
 - if python is slow and system heavy i will rewirte it in go 
---
#### to do:
 - part 1:
    - [ ] Detect new downloads
    - [ ] Wake up when a new file appears
    - [ ] Scan the file with ClamAV
    - [ ] Log the result
    - [ ] Move infected files to quarantine
    - [ ] Return to idle

