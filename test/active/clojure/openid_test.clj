(ns active.clojure.openid-test
  (:require [active.clojure.openid :as openid]
            [clojure.test :as t]
            [active.clojure.config :as active-config]
            [active.clojure.openid.config :as openid-config]
            [clojure.string :as string]
            [ring.util.codec :as codec]))

(def config-map
  {:openid
   [{:name          "keycloak"
     :host          "localhost"
     :port          8080
     :scheme        "http"
     :realm         "active-group"
     :client        "openid-test"
     :client-secret "<redacted>"
     :scopes        ["username" "email"]
     :launch-uri    "/auth/login"
     :redirect-uri  "/auth/login-callback"
     :logout-uri    "/auth/logout"
     :basic-auth?   true}]})

(def config (active-config/make-configuration (active-config/schema "Test configuration schema"
                                                                    openid-config/section)
                                              []
                                              config-map))

(def openid-profiles
  [(openid/make-openid-profile "profile"
                               (openid/make-openid-provider-config
                                "host:port/auth"
                                "host:port/token"
                                "host:port/userinfo"
                                "host:port/end_session"
                                "host:port/check_session_iframe"
                                false)
                               "client-id"
                               "client-secret"
                               ["scope"]
                               "/login"
                               "/login-callback"
                               "/"
                               "/logout"
                               false)])

(t/deftest launch-uri-test
  (t/is (= "/profile/login" (openid/launch-uri (first openid-profiles)))))

(t/deftest redirect-uri-test
  (t/is (= "/profile/login-callback" (openid/redirect-uri (first openid-profiles)))))

(t/deftest req->access-tokens-test
  (t/testing "with no access tokens, returns nil"
    (t/is (nil? (openid/req->access-tokens {}))))
  (t/testing "returns all access tokens"
    (t/is (= {"profile" {:token "some-token"}
              "other"   {:token "some-other-token"}}
             (openid/req->access-tokens {:session {::openid/access-tokens {"profile" {:token "some-token"}
                                                                           "other"   {:token "some-other-token"}}}})))))

(t/deftest req->access-token-for-openid-profile-test
  (t/testing "with no access tokens, returns nil"
    (t/is (nil? (openid/req->access-token-for-profile {} (first openid-profiles)))))
  (t/testing "with no access tokens, returns nil"
    (t/is (= "token"
             (openid/req->access-token-for-profile
              {:session {::openid/access-tokens {"profile" {:token "token"}}}}
              (first openid-profiles))))))

(t/deftest req->openid-profile
  (t/testing "with no session, returns nil"
    (t/is (nil? (openid/req->openid-profile {} openid-profiles))))
  (t/testing "returns the openid-profile"
    (t/is (= (first openid-profiles)
             (openid/req->openid-profile {:session {::openid/access-tokens {"profile" {:token "some-token"}}}}
                                         openid-profiles)))))
