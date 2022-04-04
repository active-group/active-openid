build:
	clojure -T:active-openid/build jar
.PHONY: build

release:
	clojure -T:active-openid/build release
.PHONY: release

test:
	clojure -X:active-openid/test
.PHONY: test
