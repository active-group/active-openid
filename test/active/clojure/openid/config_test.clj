(ns active.clojure.openid.config-test
  (:require [active.clojure.openid.config :as openid-config]
            [active.clojure.config :as active-config]
            [clojure.test :as t]))


(def config-map
  {:openid-profiles
   [{:provider      {:name       "profile-name"
                     :uri-prefix "profile-prefix"
                     :config-uri "http://localhost:8080/realms/active-group/.well-known/openid-configuration"}
     :client        {:id          "openid-test"
                     :secret      "<redacted>"
                     :scopes      ["openid" "username" "email"]
                     :basic-auth? true
                     :base-uri    "http://localhost:8888"}
     :callback-uris {:launch-uri   "/auth/login"
                     :redirect-uri "/auth/login-callback"
                     :landing-uri  "/login"
                     :logout-uri   "/auth/logout"}}]})

(def config (active-config/make-configuration openid-config/openid-schema
                                              []
                                              config-map))

(t/deftest t-config-seq
  (t/is (= (:openid-profiles config-map)
           (mapv active-config/configuration-object (active-config/section-subconfig config openid-config/openid-profiles-section)))))
