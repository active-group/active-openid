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

(def openid-provider-schema
  (config/schema "The openid provider schema"
                 openid-provider-name
                 openid-provider-config-uri))

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

(def openid-client-user-info-from
  (config/setting
   :user-info-from
   "Where to get the user info from:
    - `:jwt` gets it from the access token's JWT (default)
    - `:endpoint` uses a HTTP request to get it from the
      IDP's user info endpoint."
   (config/one-of-range #{:jwt :endpoint} :jwt)))

(def openid-client-schema
  (config/schema "The openid client schema."
                 openid-client-id
                 openid-client-secret
                 openid-client-scopes
                 openid-client-base-uri
                 openid-client-user-info-from))

(def openid-client-section
  (config/section :client openid-client-schema))

(def openid-proxy-host
  (config/setting
   :proxy-host
   "Proxy host."
   (config/optional-range config/string-range)))

(def openid-proxy-port
  (config/setting
   :proxy-port
   "Proxy port."
   (config/optional-range (config/integer-between-range 0 65534 3128))))

(def openid-proxy-user
  (config/setting
   :proxy-user
   "Proxy user."
   (config/optional-range config/string-range)))

(def openid-proxy-pass
  (config/setting
   :proxy-pass
   "Proxy password."
   (config/optional-range config/string-range)))

(def openid-proxy-ignore-hosts
  (config/setting
    :proxy-ignore-hosts
    "List of hosts for what proxy settings should be ignored."
    (config/optional-range (config/sequence-of-range config/string-range))))

(def openid-proxy-schema
  (config/schema
    "Schema for proxy settings.
    Modelled on puropse after `http-client`'s proxy settings
    https://github.com/dakrone/clj-http#proxies to be able to pass them on
    easily.  This needs to be addressed if client or format changes."
    openid-proxy-host
    openid-proxy-port
    openid-proxy-user
    openid-proxy-pass
    openid-proxy-ignore-hosts))

(def openid-proxy-section
  (config/section
    :proxy
    openid-proxy-schema))

(def openid-profile-schema
  (config/schema "Configuration schema for the openid connect configuration."
                 openid-provider-section
                 openid-client-section
                 openid-proxy-section))

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
