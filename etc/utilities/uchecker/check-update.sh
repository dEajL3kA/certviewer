#!/bin/bash
read -r -d '' my_sites <<-EOF
	https://deajl3ka.github.io/certviewer
	https://codeberg.org/dEajL3kA/CertViewer/raw/branch/website
	https://gitlab.com/deajl3ka1/CertViewer/-/raw/website
EOF

unset checksum_previous
set -eo pipefail

for site in ${my_sites}; do
	checksum=$(wget -q --no-check-certificate -O - "${site}/api/latest-version.txt" | dos2unix | head -n 2 | sha1sum -b | head -c 40)
	printf "%s <- %s\n" "${checksum}" "${site}"
	if [[ -n "${checksum_previous}" && "${checksum_previous}" != "${checksum}" ]]; then
		echo "Error: Checksum mismtach detected!"
		exit 1
	fi
	checksum_previous="${checksum}"
done

echo "Completed successfully."
