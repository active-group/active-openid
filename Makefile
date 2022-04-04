.PHONY: build deploy test

build:
	clojure -T:active-openid/build jar

deploy:
	clojure -T:active-openid/build reploy

test:
	clojure -X:active-openid/test
