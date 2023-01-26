(ns active.clojure.openid.config
  "Configuration schema for OpenID identity providers."
  (:require [active.clojure.config :as config]))

;; openid
(def openid-provider-name
  (config/setting
   :name
   "The name of the profile."
   config/string-range))

(def openid-provider-config-uri
  (config/setting
   :config-uri
   "The .well-known configuration uri of the openid provider."
   config/string-range))

(def openid-provider-uri-prefix
  (config/setting
   :uri-prefix
   "A prefix, which will be prepended to the callback-uris."
   (config/default-string-range "")))

(def openid-provider-schema
  (config/schema "The openid provider schema"
                 openid-provider-name
                 openid-provider-config-uri
                 openid-provider-uri-prefix))

(def openid-provider-section
  (config/section :provider openid-provider-schema))

(def openid-client-id
  (config/setting
   :id
   "A string that identifies PhoenixNG at the openid identity provider."
   (config/default-string-range "phoenix-ng")))

(def openid-client-secret
  (config/setting
   :secret
   "The secret that acts as a password for the `:client` at the idp."
   config/string-range))

(def openid-client-scopes
  (config/setting
   :scopes
   "The scopes to fetch from the idp."
   (config/sequence-of-range config/string-range)))

(def openid-client-base-uri
  (config/setting
   :base-uri
   "The base (root) uri of the application using active-openid."
   config/string-range))

(def openid-client-schema
  (config/schema "The openid client schema."
                 openid-client-id
                 openid-client-secret
                 openid-client-scopes
                 openid-client-base-uri))

(def openid-client-section
  (config/section :client openid-client-schema))

(def openid-profile-schema
  (config/schema "Configuration schema for the openid connect configuration."
                 openid-provider-section
                 openid-client-section))

(def openid-profiles-schema
  (config/sequence-schema
   "A sequence of openid identity provider configurations."
   openid-profile-schema))

(def openid-profiles-section
  (config/section
    :openid-profiles
    openid-profiles-schema))

(def openid-schema
  (config/schema
    "Configuration schema for active-openid."
    openid-profiles-section))
