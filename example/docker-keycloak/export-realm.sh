#!/bin/sh
docker-compose stop keycloak

docker-compose -f docker-compose.yml -f docker-compose-export.yml up -d keycloak

sleep 10

docker-compose -f docker-compose.yml -f docker-compose-export.yml exec keycloak /opt/keycloak/bin/kc.sh --verbose export --dir /tmp/export/ --users realm_file # --realm active-openid-example-realm

docker-compose -f docker-compose.yml -f docker-compose-export.yml stop keycloak

mv docker-keycloak/export/* docker-keycloak/import/
