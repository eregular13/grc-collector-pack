# LAB ONLY: SMB signing disabled + guest share on purpose.
FROM alpine:3.20
RUN apk add --no-cache samba && mkdir -p /srv/share && echo lab > /srv/share/lab.txt
COPY smb.conf /etc/samba/smb.conf
EXPOSE 445
CMD ["smbd", "--foreground", "--no-process-group", "--debug-stdout"]
