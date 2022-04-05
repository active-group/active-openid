(ns active.clojure.openid.config
  "Configuration schema for OpenID identity providers."
  (:require [active.clojure.config :as config]))

;; openid
(def openid-name
  (config/setting
   :name
   "The name of the profile."
   config/string-range))

(def openid-host
  (config/setting
   :host
   "The host the openid service is hosted on."
   config/string-range))

(def openid-scheme
  (config/setting
   :scheme
   "The scheme to use to connect to the idp."
   (config/one-of-range #{"http" "https"} "http")))

(def openid-port
  (config/setting
   :port
   "The port the openid service is listening on."
   (config/integer-between-range 0 65534 1553)))

(def openid-realm
  (config/setting
   :realm
   "The realm PhoenixNG belongs to."
   (config/default-string-range "rtp1")))

(def openid-client
  (config/setting
   :client
   "A string that identifies PhoenixNG at the openid identity provider."
   (config/default-string-range "phoenix-ng")))

(def openid-client-secret
  (config/setting
   :client-secret
   "The secret that acts as a password for the `:client` at the idp."
   config/string-range))

(def openid-scopes
  (config/setting
   :scopes
   "The scopes to fetch from the idp."
   (config/sequence-of-range config/string-range)))

(def openid-launch-uri
  (config/setting
   :launch-uri
   "The relative uri that initiates the authentication process."
   config/string-range))

(def openid-redirect-uri
  (config/setting
   :redirect-uri
   "The relative uri that serves as the callback endpoint to the authentication process."
   config/string-range))

(def openid-landing-uri
  (config/setting
   :landing-uri
   "The relative uri a user will be redirected to after a logout."
   config/string-range))

(def openid-logout-uri
  (config/setting
   :logout-uri
   "The relative uri that serves as the logout endpoint."
   config/string-range))

(def openid-basic-auth?
  (config/setting
   :basic-auth?
   "???"
   (config/boolean-range false)))

(def openid-schema
  (config/schema "Configuration schema for the openid identity provider"
                 openid-name
                 openid-host
                 openid-port
                 openid-scheme
                 openid-realm
                 openid-client
                 openid-client-secret
                 openid-scopes
                 openid-launch-uri
                 openid-redirect-uri
                 openid-landing-uri
                 openid-logout-uri
                 openid-basic-auth?))

(def openid-sequence-schema
  (config/sequence-schema
   "A sequence of openid identity provider configurations."
   openid-schema))

(def section
  (config/section :openid openid-sequence-schema))
