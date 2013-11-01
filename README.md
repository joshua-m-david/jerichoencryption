Jericho Chat - Information-theoretically secure communications
==============================================================

Official website, technical design and documentation is here:
http://jerichochat.tk

Jericho Chat is a highly encrypted communications platform built on the principles of information-theoretic security using true random number generation, one-time pads for encryption and message authentication codes based on universal hashing. The goal is to deliver a free, open source, highly secure solution for citizens of the world to be free from spying, oppression, and totalitarian regimes.

Constructive feedback from anyone is welcome and you are free to contribute to the project with ideas, bug reports or source code. To contribute code, make your own fork of the master branch, edit the code and submit a pull request.

Some tips:
- Read Clean Code by Robert C. Martin.
- Keep code in the same style throughout the project.
- Ideally submit small, testable changes.
- Don't write obfuscated code, use meaninful variable names.
- Aim for quality comments every 2-3 lines explaining exactly what the code is doing and why.
- Make sure any new feature or function you write has a corresponding unit test.
- All existing unit tests must still pass and the program must still be fully functional.

Source code contributions are welcome if you are not trying to undermine the security of the software. All commits will be heavily scrutinized for weaknesses and security flaws. Introducing security flaws (intentional or otherwise) will result in you being blacklisted from further contributions.

Road map / To do list:
- Allow users to include own entropy from their own trusted sources.
- Multi user server architecture.
- Encryption of API credentials in transit without reliance on TLS for protection.
- Encryption of API credentials in database per user.
- Mobile device support (Firefox OS, Android, iOS).
- Group chat (between 2 or more people).
- UTF-8 support to support multiple languages.
- Build into Firefox or Chrome extension.