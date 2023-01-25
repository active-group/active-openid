#!/bin/sh
docker-compose stop keycloak

docker-compose run --entrypoint /opt/keycloak/bin/kc.sh keycloak --verbose export --dir /tmp/export/ --realm active-openid-example-realm

mv docker-keycloak/export/* docker-keycloak/import/
