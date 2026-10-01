# Test mail server for integration tests: Dovecot 2.3 + Postfix, like mailcow.
# TLS certificates are copied to /certs by the test fixture before it starts.
FROM debian:bookworm-slim
RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
       dovecot-imapd dovecot-lmtpd postfix ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd -g 5000 vmail && useradd -u 5000 -g vmail -d /var/mail -s /usr/sbin/nologin vmail \
    && mkdir -p /var/mail && chown vmail:vmail /var/mail
COPY dovecot.conf /etc/dovecot/dovecot.conf
COPY users /etc/dovecot/users
RUN touch /etc/dovecot/app-passwords
COPY main.cf.settings submission.cf sender_login virtual_aliases transport /etc/postfix/
RUN while IFS= read -r setting; do postconf -e "$setting"; done < /etc/postfix/main.cf.settings \
    && cat /etc/postfix/submission.cf >> /etc/postfix/master.cf \
    && postconf -F '*/*/chroot = n' \
    && echo mail.test > /etc/mailname
COPY entrypoint.sh /entrypoint.sh
EXPOSE 143 993 25 587 465
ENTRYPOINT ["/bin/sh", "/entrypoint.sh"]
