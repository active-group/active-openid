(ns active.clojure.openid-test
  (:require [active.clojure.openid :as openid]
            [clojure.test :as t]
            [active.clojure.config :as active-config]
            [active.clojure.openid.config :as openid-config]
            [clojure.string :as string]
            [ring.util.codec :as codec]))

(def config-map
  {:openid
   [{:provider      {:name       "profile-name"
                     :uri-prefix "profile-prefix"
                     :config-uri "http://localhost:8080/realms/active-group/.well-known/openid-configuration"}
     :client        {:id          "openid-test"
                     :secret      "<redacted>"
                     :scopes      ["openid" "username" "email"]
                     :basic-auth? true}
     :callback-uris {:launch-uri   "/auth/login"
                     :redirect-uri "/auth/login-callback"
                     :landing-uri  "/login"
                     :logout-uri   "/auth/logout"}}]})

(def config (active-config/make-configuration (active-config/schema "Test configuration schema"
                                                                    openid-config/section)
                                              []
                                              config-map))

(def openid-profiles
  [(openid/make-openid-profile "profile-name"
                               "profile-prefix"
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
  (t/is (= "/profile-prefix/login" (openid/launch-uri (first openid-profiles)))))

(t/deftest redirect-uri-test
  (t/is (= "/profile-prefix/login-callback" (openid/redirect-uri (first openid-profiles)))))

(t/deftest req->access-tokens-test
  (t/testing "with no access tokens, returns nil"
    (t/is (nil? (openid/req->access-tokens {}))))
  (t/testing "returns all access tokens"
    (t/is (= {"profile-name" {:token "some-token"}
              "other"   {:token "some-other-token"}}
             (openid/req->access-tokens {:session {::openid/access-tokens {"profile-name" {:token "some-token"}
                                                                           "other"   {:token "some-other-token"}}}})))))

(t/deftest req->access-token-for-openid-profile-test
  (t/testing "with no access tokens, returns nil"
    (t/is (nil? (openid/req->access-token-for-profile {} (first openid-profiles)))))
  (t/testing "with no access tokens, returns nil"
    (t/is (= "token"
             (openid/req->access-token-for-profile
              {:session {::openid/access-tokens {"profile-name" {:token "token"}}}}
              (first openid-profiles))))))

(t/deftest req->openid-profile
  (t/testing "with no session, returns nil"
    (t/is (nil? (openid/req->openid-profile {} openid-profiles))))
  (t/testing "returns the openid-profile"
    (t/is (= (first openid-profiles)
             (openid/req->openid-profile {:session {::openid/access-tokens {"profile-name" {:token "some-token"}}}}
                                         openid-profiles)))))
