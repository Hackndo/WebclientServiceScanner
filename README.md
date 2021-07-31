# WebClient Service Scanner


![Example](https://raw.githubusercontent.com/Hackndo/WebclientServiceScanner/master/assets/demo.png)


Python tool to Check running WebClient services on multiple targets based on [@tifkin_ idea](https://twitter.com/tifkin_/status/1419806476353298442).

This tool uses [impacket](https://github.com/SecureAuthCorp/impacket) project.


### Usage

```bash
webclientservicescanner hackn.lab/user:S3cur3P4ssw0rd@10.10.10.0/24
```

Provided credentials will be tested against a domain controller before scanning so that a typo in the domain/username/password won't lock out the account. If you want to bypass this check, just use `-no-validation` flag.
