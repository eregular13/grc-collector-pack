#!/bin/sh
# Run Lynis + OpenSCAP against THIS lab container only.
# Writes raw report.dat + XCCDF results under /drop.
# Not a CIS profile. ANSSI/standard SSG only. Never scans a public target.
set -eu

HOST="${LAB_HOSTNAME:-$(hostname)}"
DEST="${1:-/drop}"
mkdir -p "$DEST"

# Lynis: report.dat is the ingest format host_wazuh already parses.
lynis audit system --quick --no-colors --auditor LAB \
  --report-file "$DEST/lynis-${HOST}.dat" \
  --log-file "$DEST/lynis-${HOST}.log" \
  || true

# Prefer ANSSI, then standard. Never a CIS-branded profile.
CONTENT=""
for cand in \
  /usr/share/xml/scap/ssg/content/ssg-debian12-ds.xml \
  /usr/share/xml/scap/ssg/content/ssg-debian-ds.xml \
  /usr/share/xml/scap/ssg/content/ssg-debian11-ds.xml
do
  if [ -f "$cand" ]; then
    CONTENT="$cand"
    break
  fi
done

if [ -n "$CONTENT" ]; then
  PROFILE=""
  for p in \
    xccdf_org.ssgproject.content_profile_anssi_bp28_minimal \
    xccdf_org.ssgproject.content_profile_standard \
    xccdf_org.ssgproject.content_profile_stig
  do
    if oscap info "$CONTENT" 2>/dev/null | grep -q "$p"; then
      PROFILE="$p"
      break
    fi
  done
  if [ -n "$PROFILE" ]; then
    oscap xccdf eval --profile "$PROFILE" \
      --results "$DEST/openscap-${HOST}.xml" \
      "$CONTENT" || true
  else
    oscap xccdf eval --results "$DEST/openscap-${HOST}.xml" \
      "$CONTENT" || true
  fi
else
  printf '%s\n' "oscap content missing; wrote Lynis only" > "$DEST/openscap-${HOST}.skipped.txt"
fi
