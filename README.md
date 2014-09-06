### Jericho Chat - Information-theoretically secure communications
#### Copyright (C) 2013-2014  Joshua M. David


Jericho Chat is an encrypted communications program built on the principles of information-theoretic security using true random number generation and one-time pads. The goal is to deliver a free, open source, encrypted communications program for journalists, lawyers, activists and citizens of the world that need high assurances that their communications are free of censorship, control, oppression, totalitarian governments and eavesdropping from the world's most powerful intelligence agencies. To defeat the world's best intelligence agencies, you need to lift your game to their level. That means using encryption that they can never, ever break, regardless of advances in mathematics, quantum physics, cryptanalysis or technology.

The official website, technical design, signed source code and documentation can be found here:
http://jerichochat.tk

Constructive feedback from anyone is welcome and you are free to contribute to the project with ideas, bug reports or source code. To contribute code, make your own fork of the master branch, edit the code and submit a pull request. For questions and suggestions, make a post on GitHub.

Suggestions and source code contributions are welcome if you are not trying to undermine the security of the software. All commits will be heavily scrutinized for weaknesses and security flaws. Introducing security flaws or insecure ideas (intentional or otherwise) will result in you being blacklisted from further contributions.

If you are working on this project, it is preferred that you stay anonymous. Do not mention you are working on the project to anyone using your real identity unless you want to be added to various watch lists, no-fly lists and made a target for surveillance. As a developer, gaining a trusted reputation within the project team and then later on receiving a National Security Letter (or equivalent) which forces you to subtly compromise your code also affects the project. For your safety and the project's, connect to the website and GitHub only via internet cafes, WiFi hotspots and libraries. Ideally use anonymous methods as well such as Tor or your own proxy servers.

Other ways to help:
- Maintaining the main website, design and documentation.
- Spread the word about the program.

Some tips for developers:
- Download the original source code from the website or Freenet and verify the file using the GPG signature (Key ID C467B6D0).
- Read Clean Code by Robert C. Martin.
- Keep code in the same style throughout the project.
- Tabs for indentation, spaces for alignment.
- Do not write obfuscated code or submit minified code, use meaningful variable names.
- Aim for quality comments every 2-3 lines explaining exactly what the code is doing and why.
- Comments are part of the code, keep them up to date with the code.
- The project uses QUnit and PHPUnit for unit testing. Make sure any new feature or function you write has corresponding unit test cases.
- Ideally submit small changes with corresponding unit tests if necessary.
- All existing unit tests must still pass and the program must still be fully functional.

Road map / To do list:
- Encrypt the one-time pad storage text file before exporting for transit and at all times inside the local database. (v1.4)
- Allow users to include their own entropy from their own trusted TRNG. (v1.4)
- Convert to single page app. (v1.4)
- Tablet and mobile phone support (Firefox and Chrome on Android). (v1.4)
- Optimise code so all CPU intensive processing is done inside HTML5 web workers (1.4)
- Shorten message length to 50 bytes and allow long messages to be automatically split into multiple OTPs
- UTF-8 support to support multiple languages. (v1.5)
- Mobile phone support (Firefox OS). (v1.5)
- Build into Firefox and/or Chromium extension. (future)

Setting up the development environment:
- Download the code from the site.
- Verify the download using the GPG signature and hashes provided on the site.
- Transfer the source code to a non-internet connected, air-gapped machine for development.
- Follow the server and client setup guide on the site.
- To enable debug HTTP error codes for the server protocol, set the flag 'testResponseHeaders' to true in the server/config/config.php file.
- For PHP testing:
  - Install PHPUnit by following instructions here:
    http://phpunit.de/getting-started.html
  - In /etc/php5/cli/php.ini (php.ini for the CLI) you need to edit the file and tell it to load the Skein hash extension so include the line:
    extension=skein.so
  - Then change directory (cd) to the directory containing the server files e.g. /var/www/jericho/server/ and run this on the command line:
    phpunit tests.php
