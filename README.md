# zw_universal_decoder
A universal extractor for hidden data encoded using zero-width and invisible Unicode characters. A universal extractor for hidden data encoded using **zero-width and invisible Unicode characters**.

This kind of technique is sometimes used in CTFs and challenges, like the [TryHackMe "Impossible Challenge"] (https://tryhackme.com/room/theimpossiblechallenge), where flags or secrets are hidden using Unicode tricks.   

![1](https://github.com/user-attachments/assets/1ad68d0b-96fd-40a2-91fd-0ec38d191e7f)                                                                                                                                      

<img width="1258" height="361" alt="image" src="https://github.com/user-attachments/assets/8f53fdc7-f0e2-4394-933c-e29b852a6bf4" />

--------


🟢🟢🟢How It Works🟢🟢

Zero-width characters (like `U+200C`, `U+200D`, `U+FEFF`, `U+202C`) look invisible in text, but they can secretly encode bits of data.  

Example:

Count characters (visible vs actual bytes)                                                                                                                                                                                 
wc -m thm.txt                                                                                                                                                                                                              
164 thm.txt

wc -c thm.txt                                                                                                                                                                                                              
484 thm.txt


Here the file looks small, but the byte count is much larger → hidden data is embedded.


Inspect with hexdump:

hexdump -C thm.txt | head                                                                                                                                                                                                  
00000000  e2 80 8c e2 80 8c e2 80  8c e2 80 8c e2 80 8d ef  |................|
00000010  bb bf e2 80 8c e2 80 8c  48 6d 6d e2 80 8c e2 80  |........Hmm.....|

Notice the repeating e2 80 8c etc. → those are zero-width spaces encoding the hidden message.

---------------------------

🟢👨👨Usage👨👨🟢

This tool automates detection and decoding:

python3 zw_universal_decoder.py hidding-message.txt

🟢Default mode = analyze & show candidates

🟢--secret-only = extract only the hidden text

🟢--aggressive = try extra decoding strategies

---------------------------

🎯 Why Use This?

If you encounter text in a CTF (or bug bounty challenge) that looks normal but the file size / Unicode count doesn’t match, it may hide a secret.

Instead of manually guessing, this tool will try multiple decoding heuristics and reveal messages
