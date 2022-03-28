(ns active.clojure.oidc.config
  "Configuration schema for Keycloak oidc identity providers."
  (:require [active.clojure.config :as config]))

;; oidc
(def oidc-name
  (config/setting
   :name
   "The name of the profile."
   config/string-range))

(def oidc-host
  (config/setting
   :host
   "The host the oidc service is hosted on."
   config/string-range))

(def oidc-scheme
  (config/setting
   :scheme
   "The scheme to use to connect to the idp."
   (config/one-of-range #{"http" "https"} "http")))

(def oidc-port
  (config/setting
   :port
   "The port the oidc service is listening on."
   (config/integer-between-range 0 65534 1553)))

(def oidc-realm
  (config/setting
   :realm
   "The realm PhoenixNG belongs to."
   (config/default-string-range "rtp1")))

(def oidc-client
  (config/setting
   :client
   "A string that identifies PhoenixNG at the oidc identity provider."
   (config/default-string-range "phoenix-ng")))

(def oidc-client-secret
  (config/setting
   :client-secret
   "The secret that acts as a password for the `:client` at the idp."
   config/string-range))

(def oidc-scopes
  (config/setting
   :scopes
   "The scopes to fetch from the idp."
   (config/sequence-of-range config/string-range)))

(def oidc-launch-uri
  (config/setting
   :launch-uri
   "The relative uri that initiates the authentication process."
   config/string-range))

(def oidc-redirect-uri
  (config/setting
   :redirect-uri
   "The relative uri that serves as the callback endpoint to the authentication process."
   config/string-range))

(def oidc-landing-uri
  (config/setting
   :landing-uri
   "The relative uri a user will be redirected to after a logout."
   config/string-range))

(def oidc-logout-uri
  (config/setting
   :logout-uri
   "The relative uri that serves as the logout endpoint."
   config/string-range))

(def oidc-basic-auth?
  (config/setting
   :basic-auth?
   "???"
   (config/boolean-range false)))

(def oidc-schema
  (config/schema "Configuration schema for the openid identity provider"
                 oidc-name
                 oidc-host
                 oidc-port
                 oidc-scheme
                 oidc-realm
                 oidc-client
                 oidc-client-secret
                 oidc-scopes
                 oidc-launch-uri
                 oidc-redirect-uri
                 oidc-landing-uri
                 oidc-logout-uri
                 oidc-basic-auth?))

(def oidc-sequence-schema
  (config/sequence-schema
   "A sequence of oidc identity provider configurations."
   oidc-schema))

(def section
  (config/section :openid-connect oidc-sequence-schema))
