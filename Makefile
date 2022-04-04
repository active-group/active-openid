build:
	clojure -T:active-openid/build jar
.PHOHNY: build

release:
	clojure -T:active-openid/build release
