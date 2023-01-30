.PHONY: test jar deploy snapshot install deploy-snapshot

test:
	clojure -X:active-openid/test


jar:
	clojure -T:active-openid/build jar

deploy:
	clojure -T:active-openid/build deploy


snapshot:
  clojure -T:active-openid/build snapshot

install:
	clojure -T:active-openid/build install-snapshot

deploy-snapshot:
	clojure -T:active-openid/build deploy-snapshot
