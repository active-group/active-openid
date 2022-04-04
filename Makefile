build:
	clojure -T:active-keycloak/build jar
.PHOHNY: build
