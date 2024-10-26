### Jericho Comms - Information-theoretically secure communications
#### Copyright (c) 2013-2024  Joshua M. David


Jericho Comms is an encrypted communications program built on the principles of information-theoretic security using true random number generation and one-time pads. The goal is to deliver a free, open source, encrypted communications program for journalists, lawyers, activists and citizens of the world that need high assurances that their communications are free of censorship, control, oppression, totalitarian governments and eavesdropping from the world's most powerful intelligence agencies. To defeat the world's best intelligence agencies, you need to lift your game to their level. That means using encryption that they can never break, regardless of advances in computing power, mathematics, cryptanalysis or quantum physics.

The official website, technical design, signed source code and documentation can be found here:
https://joshua-m-david.github.io/jerichoencryption/


Constructive feedback from anyone is welcome and you are free to contribute to the project with ideas, designs. bug reports, source code or code reviews. To contribute code, make your own fork of the master branch, edit the code and submit a pull request. For questions and suggestions, make an issue on GitHub.

Suggestions and source code contributions are welcome if you are not trying to undermine the security of the software. All commits will be heavily scrutinised for weaknesses and security flaws. Introducing security flaws or insecure ideas (intentional or otherwise) will result in you being blacklisted from further contributions.

If you are working on this project, it is preferred that you stay anonymous. Do not mention you are working on the project to anyone using your real identity unless you want to be added to various watch lists, no-fly lists and made a target for surveillance. As a developer, gaining a trusted reputation within the project team and then later on receiving a National Security Letter (or equivalent) which forces you to subtly compromise your code also affects the project. For your safety and the project's, connect to the website and GitHub only via internet cafes, WiFi hotspots, libraries, proxy or VPN. Then connect from there to an anonymising network such as Tor as well before visiting the site.

Other ways to help:

- Cryptanalysis and security analysis of the design.
- Security code audits.
- Maintaining the main website and whitepaper (see gh-pages branch).
- Improvements to UX, UI design and icons.
- Documentation improvements.
- User testing and bug reporting.
- Marketing and spreading the word about the program.
- User technical support.
- Donations to fund cryptography/security reviews, code audits and future development.

Road map / To do list:

- Allow long messages to be automatically split into multiple OTP encrypted messages on the client then recombined on the receiving end. (next release)
- Fix file permissions for all files in client and server dirs, only read/write for current user ref: https://serverfault.com/a/357109 (next release)
- Allow sending/receiving to multiple servers to to prevent DDOS, prevent message routing issues e.g. censorship, interference and provide high availability. (future)
- Poly1305 One-time MAC with unique one-time keys per message as the natural information-theoretically secure MAC pairing for the one-time pad with integrity guarantee. (future)
- Encrypt the one-time pad database at all times inside the local database, password required if session closed or page refreshed. (future)
- Add backtracking protection for Salsa20 fallback RNG i.e. Fast Key Erasure RNG https://blog.cr.yp.to/20170723-random.html. (future)
- Record voice snippets with microphone, convert to binary and split into multiple OTP encrypted messages then recombined on the receiving end. (future)
- Randomise order of installing dependencies for the server code to prevent potential fingerprinting. (future)
- Increase font sizes to at least 14px to make it more legible. (future)
- Common header/footer and hamburger menu, redesign chat screen. (future)
- Randomise "Server: name" in server header responses to use different web servers and versions to disguise what the server is really running. (future)
- Export one time pads to image file / load from image file (encode as bytes into the RGB values or as LSBs of another file) to make importing easier (or for steganographic purposes). (future)
- Tablet and mobile screen size support (Firefox and Chromium on Android). (future)
- Allow different groups to communicate in the chat interface rather than separate tabs & folder locations. (future)
- Use IndexedDB for larger local storage and capacity to handle multiple groups in one app. (future)
- Optimise code so all CPU intensive processing is done inside HTML5 web workers and parallelised if they have more than 2 cores. (future)
- Convert existing code to use ES6+ language syntax with const/let, async/await etc. (future)
- Remove jQuery reliance and just use vanilla JS. (future)
- Add sources / links to libraries (if necessary host myself). (future)
- Move or clone code base to GitLab or other provider (after Microsoft takeover of GitHub). (future)
- Build into Firefox and/or Chromium WebExtension. (future)
- Build into Android/iOS app with Progressive Web App or desktop app with Electron or similar application. (future)
- Dark theme for night operation. (future)
- Interface translated into most common languages. (future)
- Remove usages of substr() and use substring() - considered a legacy feature in ECMAScript and could be removed from future versions (future)
- Add information about bug bounty e.g. paid in cryptocurrency. (future)

Some tips for developers:

- Download the original source code from the website and verify the file using the GPG signature (Key ID 0xDC768471C467B6D0 and Fingerprint CF3F 79EE 0114 59BA 0A59 9E9C DC76 8471 C467 B6D0).
- Verify the fingerprint on https://onename.com/joshua_m_david and https://keybase.io/joshua_m_david.
- Read Clean Code by Robert C. Martin.
- Keep code in the same style throughout the project.
- Tabs for indentation, spaces for alignment.
- Do not write obfuscated code or submit minified code. Use meaningful variable names.
- Aim for quality comments every 1-3 lines explaining exactly what the code is doing and why.
- Comments are a critical part of the code, keep them up to date with the code.
- The project currently uses QUnit and PHPUnit for unit testing. Make sure any new feature or function you write has
  corresponding unit test cases.
- Ideally submit small changes with corresponding unit tests if necessary.
- All existing unit tests must still pass and the program must still be fully functional.
- Sign your commits with your GnuPG key (>= 4096 bits). Your public key should be verifiable on a blockchain e.g. in
  keybase.io or Namecoin.
- Don't use jQuery's .html() to set HTML, it needs to be escaped for XSS. Use .text() or / JavaScript's native
  .textContent() preferably.
- Don't use IDs for HTML elements. It's a full page app so we don't want any conflicts across pages.
- The code follows these guidelines https://philipwalton.com/articles/decoupling-html-css-and-javascript/ for keeping
  the HTML, JS and CSS decoupled as much as possible. For elements used by the JS exclusively they will be prefixed
  with 'js' e.g. '.jsChatInput' for referencing the chatInput element. For elements that have styling and may be
  toggled on/off or referenced by the JS they will be prefixed with 'is' e.g. '.isMessageReceived' for toggling a
  class that this is a message that was received from another user (not sent), so care must be taken when refactoring
  the HTMl/CSS and changing those styles that it does not break the JS. Classes without any 'is' or 'js' prefixes can
  be freely refactored by editing just the HTML and CSS without breaking any critical JS functionality.

Setting up the development environment:

- Download the code from the site.
- Download and verify the GPG signature and hashes provided on the site.
- Transfer the source code to a non-internet connected, air-gapped machine for development.
- Follow the server and client setup guide on the site.
- To enable debug HTTP error codes for the server protocol, set the flag `testResponseHeaders` to `true` in the `server/config/config.php` file.
- Optionally install pgAdmin for managing PostgreSQL e.g. `sudo apt-get -y install pgadmin4`.

Emergency hashes:

1. 21aa4423186373bb060dc1ff85284edfc65181654537773fc0617a7447fe6bb4a1dd7a16ef2a3cb450bcca84d4d97b16
2. 3137a69e91548f850f6de77ba9257eb740b16ca46174cb065f09120e7298eefd4088277d267c4f492a5d5279130f0747
3. 8e14164e00dd66ad8ebcfc3852865c225c3186b3982bd3dba746db4c0dcdd20068b3bb0a6c0b96855ff6199c964f26ab
4. db3ccea4a00c39a6d1b9854e7cf6c7eaa4d62bb62a55dd4553d6eec25ed2096f87a8d7cb5bac426dd352a474f9b85107
5. 4566d810a59b30253b9b99cced4248df856e65befadc6226b4c09c388f613708931aea919ea54af0dc243dfd4f582907
