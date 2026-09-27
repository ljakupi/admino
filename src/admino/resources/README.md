# Bundled data

## common_passwords.txt

The common/breached password list that `admino.passwords` rejects (GH-149). It is
loaded once into a set; there is no external lookup.

- Source: SecLists, `Passwords/Common-Credentials/100k-most-used-passwords-NCSC.txt`
  (the UK NCSC's 100,000 most-used passwords from the Have I Been Pwned corpus)
- Commit: `1a7bb9127eca9e6ff2fc0301c597fe6e16a0cb56`
- SHA-256: `c2e5696882c603b76bb67a47ee970897e5a76fc4c3f5547abe3d0ca340c576e0`
- License: MIT, Copyright (c) 2018 Daniel Miessler (https://github.com/danielmiessler/SecLists)

The file is shipped unmodified. To update it, replace it with a newer revision of the
same SecLists file and update the commit and checksum above.
