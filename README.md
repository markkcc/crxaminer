# CRXaminer

Rails app that examines Chrome extensions for security issues.

Hosted at: https://crxaminer.tech/

Chrome extensions can pose a risk to our data. They run within the context of our browser, and can request permissions to read and manipulate data.

Since a lot of sensitive data is handled by our web browsers, including banking and medical data, it is worth considering the risk posed by Chrome extensions to ourselves and our organizations. 

### What is a Chrome extension?

They are archives formatted as "CRX3" (as of 2019), which contain code, usually JavaScript. The archive also contains a manifest.json file, which lists the permissions requested by the extension. Once installed, that code runs within your browser, and has access to functionality listed within its permissions list, granted at time of installation. 

### What's the impact of a malicious extension?

Consider an extension that has the ability to read and write data on ALL websites, and can send and receive requests. These permissions allow it to read e.g. financial data from banking applications, and send it to a third party. 
Some extensions benignly need access to all websites to be able to function properly, such as an ad blocker, which is intended to work on all sites. 

### Should I avoid high risk extensions?

It depends on your risk appetite and threat model. It is worth putting into perspective the purpose of an extension in relation to its apparent risk. 

A high risk rating doesn't mean an extension is bad or untrustworthy. It just shows what damage could be done if the extension or its creators were to become malicious in the future (or get compromised).

### What is a CRX3 file?

It is a ZIP archive with a prepended header. The binary format is as follows:
- [4 octets]: "Cr24", a magic number.
- [4 octets]: The version of the *.crx file format used (currently 3).
- [4 octets]: N, little-endian, the length of the header section.
- [N octets]: The header (the binary encoding of a CrxFileHeader).
- [M octets]: The ZIP archive.

More details [here](https://chromium.googlesource.com/chromium/src/+/refs/tags/127.0.6483.0/components/crx_file/crx3.proto).
