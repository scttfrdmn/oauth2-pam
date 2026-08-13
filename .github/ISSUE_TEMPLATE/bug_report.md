---
name: Bug report
about: Something does not do what it says
labels: bug
---

<!-- If this is a security vulnerability, do not file it here. See SECURITY.md. -->

## What happened

<!-- And what you expected instead. "The login failed" is a start; "the login
failed after showing the code, and the code had already been approved" is
actionable. -->

## Which half

- [ ] the PAM module / login (`oauth2_pam.so`)
- [ ] the broker (`oauth2-pam-broker`)
- [ ] the mapper
- [ ] config loading or validation
- [ ] the admin CLI
- [ ] the docs
- [ ] not sure

## Versions

- oauth2-pam:
- OS and version:
- OpenSSH server version (`sshd -V` or `ssh -V`):
- GitHub or GitHub Enterprise Server (and version, if Enterprise):

<!-- OpenSSH version matters more than it looks: how it buffers PAM messages and
how it handles SSH_ASKPASS both changed across releases, and both affect whether
you ever see the device code. -->

## The PAM stanza

<!-- The relevant lines of /etc/pam.d/sshd, verbatim, including module
arguments. Whether the module is `sufficient` or `required`, and what follows
it, changes what a failure means. -->

```
```

## Broker config

<!-- /etc/oauth2-pam/broker.yaml with client_secret and token_encryption_key
removed. The mapper rules are usually the interesting part. -->

```yaml
```

## Logs

<!-- Add `debug` to the module arguments and reproduce, then include what
authpriv logged (journalctl -t oauth2_pam, or /var/log/auth.log). Broker logs
too — journalctl -u oauth2-pam-broker. Redact tokens and user codes. -->

```
```

## Reproduction

1.
2.
3.

- [ ] `make test-integration` passes on my checkout
- [ ] it does not, and the failing case is:
