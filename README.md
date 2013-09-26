Jericho Encrypted Chat
======================

Official website is here:
http://jerichoencryption.tk

Constructive feedback from anyone is welcome and you are free to contribute to the project with ideas, bug reports or source code. To contribute code, 
make your own fork of the master branch, edit the code and submit a pull request.

Some tips:
- Keep code in the same style.
- Ideally submit small, testable changes.
- Don't write obfuscated code, use meaninful variable names.
- Aim for quality comments every 2-3 lines explaining exactly what the code is doing and why.
- Make sure any new feature you write has a corresponding unit test.
- All existing unit tests must still pass and the program must still be fully functional.

Source code contributions are welcome if you do are not trying to undermine the security of the software. All commits will be heavily scrutinized for 
weaknesses and security flaws. Introducing security flaws (intentional or otherwise) will result in you being blacklisted from further contributions.

Road map:
- Allow users to include own entropy from their own trusted sources.
- Multi user server architecture
- UTF-8 support
- Encryption of API credentials in transit without reliance on TLS
- Encryption of API credentials in database per user
- Group chat (between 2 or more people)
- Mobile device support (Firefox OS, Android, iOS)
- Build into Firefox or Chrome extension