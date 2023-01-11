.PHONY: build deploy test

build:
	clojure -T:active-openid/build jar

deploy: build
	clojure -T:active-openid/build deploy

test:
	clojure -X:active-openid/test

install: build
	clojure -T:active-openid/build install
