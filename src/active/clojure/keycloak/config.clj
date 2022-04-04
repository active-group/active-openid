(ns active.clojure.keycloak.config
  "Configuration schema for Keycloak keycloak identity providers."
  (:require [active.clojure.config :as config]))

;; keycloak
(def keycloak-name
  (config/setting
   :name
   "The name of the profile."
   config/string-range))

(def keycloak-host
  (config/setting
   :host
   "The host the keycloak service is hosted on."
   config/string-range))

(def keycloak-scheme
  (config/setting
   :scheme
   "The scheme to use to connect to the idp."
   (config/one-of-range #{"http" "https"} "http")))

(def keycloak-port
  (config/setting
   :port
   "The port the keycloak service is listening on."
   (config/integer-between-range 0 65534 1553)))

(def keycloak-realm
  (config/setting
   :realm
   "The realm PhoenixNG belongs to."
   (config/default-string-range "rtp1")))

(def keycloak-client
  (config/setting
   :client
   "A string that identifies PhoenixNG at the keycloak identity provider."
   (config/default-string-range "phoenix-ng")))

(def keycloak-client-secret
  (config/setting
   :client-secret
   "The secret that acts as a password for the `:client` at the idp."
   config/string-range))

(def keycloak-scopes
  (config/setting
   :scopes
   "The scopes to fetch from the idp."
   (config/sequence-of-range config/string-range)))

(def keycloak-launch-uri
  (config/setting
   :launch-uri
   "The relative uri that initiates the authentication process."
   config/string-range))

(def keycloak-redirect-uri
  (config/setting
   :redirect-uri
   "The relative uri that serves as the callback endpoint to the authentication process."
   config/string-range))

(def keycloak-landing-uri
  (config/setting
   :landing-uri
   "The relative uri a user will be redirected to after a logout."
   config/string-range))

(def keycloak-logout-uri
  (config/setting
   :logout-uri
   "The relative uri that serves as the logout endpoint."
   config/string-range))

(def keycloak-backchannel-logout-uri
  (config/setting
   :backchannel-logout-uri
   "The relative uri that serves as the backchannel logout endpoint."
   config/string-range))

(def keycloak-basic-auth?
  (config/setting
   :basic-auth?
   "???"
   (config/boolean-range false)))

(def keycloak-schema
  (config/schema "Configuration schema for the openid identity provider"
                 keycloak-name
                 keycloak-host
                 keycloak-port
                 keycloak-scheme
                 keycloak-realm
                 keycloak-client
                 keycloak-client-secret
                 keycloak-scopes
                 keycloak-launch-uri
                 keycloak-redirect-uri
                 keycloak-landing-uri
                 keycloak-logout-uri
                 keycloak-backchannel-logout-uri
                 keycloak-basic-auth?))

(def keycloak-sequence-schema
  (config/sequence-schema
   "A sequence of keycloak identity provider configurations."
   keycloak-schema))

(def section
  (config/section :keycloak keycloak-sequence-schema))
