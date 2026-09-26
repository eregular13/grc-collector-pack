# LAB ONLY: anonymous FTP on purpose.
FROM alpine:3.20
RUN apk add --no-cache vsftpd && mkdir -p /srv/ftp/pub /var/run/vsftpd/empty \
 && echo "LAB anonymous file - not client data" > /srv/ftp/pub/README.txt
COPY vsftpd.conf /etc/vsftpd/vsftpd.conf
EXPOSE 21
CMD ["vsftpd", "/etc/vsftpd/vsftpd.conf"]
