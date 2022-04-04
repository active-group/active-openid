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
