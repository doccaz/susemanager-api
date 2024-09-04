#!/bin/bash

API="https://susemanager.suselab.localdomain/rhn/manager/api"
POSTDATA='{"login": "infobot", "password": "infobot321"}'
CMD="curl -LSks -c cookies.txt -b cookies.txt -H @headers.txt"

# faz o login
$CMD -d "${POSTDATA}" ${API}/auth/login
if [ $? -eq 0 ]; then
	echo
	echo "autenticado com sucesso"
	echo

	# executamos o comando...
	OUTPUT=$($CMD ${API}/system/getId?name=$1)

	# fazemos o logout
	# o POST data pode ser vazio, pois ele desloga usando os cookies
	$CMD -d "" ${API}/auth/logout
	if [ $? -eq 0 ]; then
		echo
		echo "logout com sucesso"
		echo
	else
		echo "erro no logout"
		exit 1
	fi
else
	echo "erro ao autenticar"
	exit 1
fi


echo "saida: $OUTPUT"
