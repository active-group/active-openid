(ns active.clojure.openid
  (:require [active.clojure.condition :as condition]
            [active.clojure.config :as active-config]
            [active.clojure.config :as config]
            [active.clojure.lens :as lens]
            [active.clojure.openid :as openid]
            [active.clojure.openid.config :as openid-config]
            [active.clojure.record :refer [define-record-type]]
            [clojure.spec.alpha :as s]
            [clj-http.client :as http-client]
            [clj-time.core :as time]
            [clojure.data.json :as json]
            [clojure.string :as string]
            [crypto.random :as random]
            [ring.middleware.cookies :as ring-cookies]
            [ring.middleware.params :refer [wrap-params]]
            [ring.util.codec :as codec]
            [ring.util.response :as response])
  (:import [java.net URI]))

(define-record-type OpenIdProviderConfig
  make-openid-provider-config openid-provider-config?
  [authorize-endpoint     openid-provider-config-authorize-endpoint
   token-endpoint         openid-provider-config-token-endpoint
   userinfo-endpoint      openid-provider-config-userinfo-endpoint
   end-session-endpoint   openid-provider-config-end-session-endpoint
   check-session-endpoint openid-provider-config-check-session-endpoint
   supports-backchannel-logout? openid-provider-config-supports-backchannel-logout?])

(define-record-type ^{:doc "Wraps all necessary information for a openid identity provider profile."}
  OpenidProfile
  make-openid-profile openid-profile?
  [name                   openid-profile-name
   openid-provider-config openid-profile-openid-provider-config
   client-id              openid-profile-client-id
   client-secret          openid-profile-client-secret
   scopes                 openid-profile-scopes
   launch-uri             openid-profile-launch-uri
   redirect-uri           openid-profile-redirect-uri
   landing-uri            openid-profile-landing-uri
   logout-uri             openid-profile-logout-uri
   basic-auth?            openid-profile-basic-auth?])

(defn prefixed-uri
  "Returns a `uri` prefixed with the name of the `openid-profile`."
  [openid-profile uri]
  (str "/" (openid-profile-name openid-profile) uri))

(defn launch-uri
  "Returns the qualified launch-uri of an `openid-profile`."
  [openid-profile]
  (prefixed-uri openid-profile (openid-profile-launch-uri openid-profile)))

(defn redirect-uri
  "Returns the qualified redirect-uri of an `openid-profile`."
  [openid-profile]
  (prefixed-uri openid-profile (openid-profile-redirect-uri openid-profile)))

(defn get-openid-configuration-url
  [scheme host port realm]
  (format "%s://%s:%d/auth/realms/%s/.well-known/openid-configuration" scheme host port realm))

(defn- openid-supports-backchannel-logout?
  ;; True if the `openid-profile` supports backchannel logouts as discovered
  ;; on the .well-known page.
  [openid-profile]
  (lens/yank openid-profile (lens/>> openid-profile-openid-provider-config
                                   openid-provider-config-supports-backchannel-logout?)))

(define-record-type OpenidInstanceNotAvailable
  make-openid-instance-not-available openid-instance-not-available?
  [tried-endpoint openid-instance-not-available-tried-instance
   error-msg openid-instance-not-available-error-msg])

(defn- get-openid-provider-config!
  ;; Based on the connection parameters, fetches the openid provider
  ;; configuration from the .well-known json object provided by the idp.

  ;; Also see [here](https://ldapwiki.com/wiki/Openid-configuration).

  ;; If the openid instance is not available, returns
  ;; an [[%openid-instance-not-available]]] condition.
  [scheme host port realm]
  (let [configuration-url (get-openid-configuration-url scheme host port realm)]
    (try (let [{:keys [status body]} (http-client/get configuration-url)]
           (case status
             200 (let [json-map (json/read-str body)]
                   (make-openid-provider-config (get json-map "authorization_endpoint")
                                                (get json-map "token_endpoint")
                                                (get json-map "userinfo_endpoint")
                                                (get json-map "end_session_endpoint")
                                                (get json-map "check_session_iframe")
                                                (get json-map "backchannel_logout_supported")))
             "error"))
         (catch Exception e
           (make-openid-instance-not-available configuration-url (.getMessage e))))))

(defn make-openid-profiles!
  "Takes a [[active.clojure.config/Configuration]] and extracts all
  configured [[OpenidProfile]]s from the config.

  If any openid instance is not available, returns
  an [[%openid-instance-not-available]]] condition instead of
  an [[OpenidProfile]] for that instance.."
  [config]
  (let [openid-profiles-config (active-config/section-subconfig config openid-config/section)]
    (mapv (fn [c]
            (let [scheme (active-config/access c openid-config/openid-scheme)
                  host   (active-config/access c openid-config/openid-host)
                  port   (active-config/access c openid-config/openid-port)
                  realm  (active-config/access c openid-config/openid-realm)
                  client (active-config/access c openid-config/openid-client)

                  ;; This might fail Also, this might be a bad idea:
                  ;; TODO If the identity provider is unavailable at
                  ;; startup, there is no recovery.
                  openid-provider-config-or-error
                  (get-openid-provider-config! scheme host port realm)]
              (cond
                (openid-provider-config? openid-provider-config-or-error)
                (make-openid-profile (active-config/access c openid-config/openid-name)
                                   openid-provider-config-or-error
                                   (active-config/access c openid-config/openid-client)
                                   (active-config/access c openid-config/openid-client-secret)
                                   (active-config/access c openid-config/openid-scopes)
                                   (active-config/access c openid-config/openid-launch-uri)
                                   (active-config/access c openid-config/openid-redirect-uri)
                                   (active-config/access c openid-config/openid-landing-uri)
                                   (active-config/access c openid-config/openid-logout-uri)
                                   (active-config/access c openid-config/openid-basic-auth?))

                (openid-instance-not-available? openid-provider-config-or-error)
                openid-provider-config-or-error)))
          openid-profiles-config)))

(defn- join-scopes
  ;; Returns a string containing all configured
  ;; [[openid-profile-scopes]], separated by `\space`.
  [openid-profile]
  (string/join " " (map name (openid-profile-scopes openid-profile))))

(defn- authorize-uri
  [openid-profile state]
  (let [authorize-uri (lens/yank openid-profile (lens/>> openid-profile-openid-provider-config
                                                       openid-provider-config-authorize-endpoint))]
    (str authorize-uri
         (if (string/includes? authorize-uri "?") "&" "?")
         (codec/form-encode {:response_type "code"
                             :client_id     (openid-profile-client-id openid-profile)
                             :redirect_uri  (redirect-uri openid-profile)
                             :state         state}))))

(defn- random-state
  []
  (-> (random/base64 9)
      (string/replace "+" "-")
      (string/replace "/" "_")))

(defn make-launch-handler
  [openid-profile]
  (fn [request]
    (let [state       (random-state)
          new-session (assoc (:session request) ::authorize-state state)]
      (-> (response/redirect (authorize-uri openid-profile state))
          (assoc :session new-session)))))

(defn- coerce-to-int [n]
  (if (string? n)
    (Integer/parseInt n)
    n))

(defn- format-access-token
  [{{:keys [access_token expires_in refresh_token id_token] :as body} :body}]
  (-> {:token      access_token
       :extra-data (dissoc body :access_token :expires_in :refresh_token :id_token)}
      (cond-> expires_in (assoc :expires (-> expires_in
                                             coerce-to-int
                                             time/seconds
                                             time/from-now))
              refresh_token (assoc :refresh-token refresh_token)
              id_token      (assoc :id-token id_token))))

(defn- get-authorization-code
  [request]
  (get-in request [:query-params "code"]))

(defn- request-params
  [openid-profile request]
  {:grant_type   "authorization_code"
   :code         (get-authorization-code request)
   :redirect_uri (redirect-uri openid-profile)})

(defn- add-header-credentials
  [options client-id client-secret]
  (assoc options :basic-auth [client-id client-secret]))

(defn- add-form-credentials
  [options client-id client-secret]
  (assoc options :form-params (-> (:form-params options)
                                  (merge {:client_id     client-id
                                          :client_secret client-secret}))))

(defn- get-access-token
  "For a `openid-profile` and based on a `request` (the response of the
  idp), fetch the actual (JWT) access token.

  Might throw an exception."
  [openid-profile request]
  (let [access-token-uri (lens/yank openid-profile (lens/>> openid-profile-openid-provider-config
                                                          openid-provider-config-token-endpoint))
        client-id        (openid-profile-client-id openid-profile)
        client-secret    (openid-profile-client-secret openid-profile)
        basic-auth?      (openid-profile-basic-auth? openid-profile)]
    (let [resp (http-client/post access-token-uri
                                 (cond-> {:accept :json, :as :json,
                                          :form-params (request-params openid-profile request)}
                                   basic-auth?       (add-header-credentials client-id client-secret)
                                   (not basic-auth?) (add-form-credentials client-id client-secret)))]
      (format-access-token resp))))

(defn- state-matches?
  ;; Checks if the state given in the original request matches the
  ;; response given by the idp.
  [request]
  (= (get-in request [:session ::authorize-state])
     (get-in request [:query-params "state"])))

(def ^:private state-mismatch-response {:status 400, :headers {}, :body "State mismatch"})
(def default-state-mismatch-handler (constantly state-mismatch-response))

(def ^:private no-auth-code-response {:status 400, :headers {}, :body "No authorization code"})
(def default-no-auth-code-handler (constantly no-auth-code-response))


;; Some specs just to make sure theres an understanding on how the
;; session part of the request-map is supposed to be structured.
(s/def ::profile-name (s/or :string string? :key keyword?))
(s/def ::token string?)
(s/def ::token_type string?)
(s/def ::extra-data (s/keys :opt-un [::token_type]))
(s/def ::token-map (s/keys :req-un [::token ::extra-data]))
(s/def ::access-tokens (s/map-of ::profile-name ::token-map))
(s/def ::session (s/keys :req [::access-tokens]))
(s/def ::request (s/keys :opt-un [::session]))

(s/fdef make-redirect-handler
  :ret (s/fspec :args (s/cat :req ::request)))
(defn make-redirect-handler
  "Creates a redirect (callback) handler for a `openid-profile`.  A
  successful login might result in an exceptional state (i.e. when
  the server cannot be reached after receiving the code.  Such
  errors will be returned as a ring-response with code 500 and the
  class and message as a Clojure-map."
  [openid-profile no-auth-code-handler state-mismatch-handler]
  (fn [{:keys [session] :as request}]
    (cond
      (not (state-matches? request))
      (state-mismatch-handler request)

      (nil? (get-authorization-code request))
      (no-auth-code-handler request)

      :else
      (try 
        (let [access-token (get-access-token openid-profile request)]
          (-> (response/redirect (openid-profile-landing-uri openid-profile))
              (assoc :session (-> session
                                  (assoc-in [::access-tokens (openid-profile-name openid-profile)] access-token)
                                  (dissoc ::authorize-state)))))
        (catch Exception e
          (-> (response/response {:message (.getMessage e)})
              (response/status 500)
              (response/header "Content-Type" "application/json")))))))

(defn- make-user-session-destroyer
  [openid-profile]
  (fn [req]
    (update-in req [:session ::access-tokens] dissoc (openid-profile-name openid-profile))))

(s/fdef req->access-tokens
  :args (s/cat :req ::request)
  :ret (s/nilable ::access-tokens))
(defn req->access-tokens
  "Returns a map of all access-tokens from a ring `req`.  The format
  is [name-of-profile access-token]."
  [req]
  (-> req :session ::access-tokens))

(s/fdef req->access-token-for-profile
  :args (s/cat :req ::request :openid-profile openid-profile?)
  :ret (s/nilable ::token))
(defn req->access-token-for-profile
  "Returns the access token for `openid-profile` if there is one."
  [req openid-profile]
  (-> (req->access-tokens req)
      (get-in [(openid-profile-name openid-profile) :token])))

(s/fdef req->access-token-type-for-profile
  :args (s/cat :req ::request :openid-profile openid-profile?)
  :ret (s/nilable ::token_type))
(defn req->access-token-type-for-profile
  "Returns the access token's type for `openid-profile` if there is
  one."
  [req openid-profile]
  (-> (req->access-tokens req)
      (get-in [(openid-profile-name openid-profile) :extra-data :token_type])))

(s/fdef req->openid-profile
  :args (s/cat :req ::request :openid-profiles (s/coll-of openid-profile?))
  :ret (s/nilable openid-profile?))
(defn req->openid-profile
  "Get the [[OpenidProfile]] out of `openid-profiles` that is used for
  `req`.  Assumes there is only one active session."
  [req openid-profiles]
  (let [access-tokens (req->access-tokens req)]
    (first (filter (fn [openid-profile]
                     (some? (req->access-token-for-profile req openid-profile)))
                   openid-profiles))))

(defn openid-logout
  "Function that performs a logout at the idp for the current user.
  Clears the whole :session for the `openid-profile`."
  [openid-profile]
  (let [end-session-endpoint
        (lens/yank openid-profile (lens/>> openid-profile-openid-provider-config
                                         openid-provider-config-end-session-endpoint))
        destroy-user-session (make-user-session-destroyer openid-profile)]
    (-> (response/redirect
         (str end-session-endpoint
              "?"
              (codec/form-encode {:post_logout_redirect_uri (str "http://localhost:1414"
                                                                 (openid-profile-landing-uri openid-profile))})))
        destroy-user-session)))

(defn reitit-routes-for-profile
  "For a given [[OpenidProfile]], returns a vector containing the launch-
  and login-callback handlers."
  [openid-profile no-auth-code-handler state-mismatch-handler]
  [[(launch-uri openid-profile)
    {:get {:handler (make-launch-handler openid-profile)}}]
   [(redirect-uri openid-profile)
    {:get {:handler    (make-redirect-handler openid-profile no-auth-code-handler state-mismatch-handler)
           :middleware [[wrap-params]]}}]])

(defn reitit-routes
  "Based on a sequence of [[OpenidProfile]]s, returns a vector of two
  reitit routes that handle the initial login launch and the openid
  callback.
  Takes an optional map with up to two keys

  - `:no-auth-code-handler`: Handler that the callback handler calls
  on the result when no authentication code is provided.  Defaults
  to [[default-no-auth-code-handler]].

  - `:state-mismatch-handler`: Handle the callback handler calls on
  the result when the state provided by this applcication doesn't
  match the state given in the response of the idp.  Defaults
  to [[default-state-mismatch-handler]].

  Each of them will be applied to _every_ profile.

  After a login attempt, the identity provider calls the provided
  callback handler which results in three possible scenarios:

  1. A valid login: The login was successful.  The callback handler
  will use the code provided by the idp and fetches an access token (a
  JWT token).  The token will be assed to the session under
  `[::access-tokens <openid-profile-name> <access-token>]`.

  2. The idp didn't provide an authorization code.  The callback
  handler returns the [[no-auth-code-response]].

  3. The state code's did not match.  The callback handle rreturns
  the [[state-mismatch-response]]."
  [openid-profiles & [{:keys [no-auth-code-handler
                            state-mismatch-handler]
                     :or   {no-auth-code-handler   default-no-auth-code-handler
                            state-mismatch-handler default-state-mismatch-handler}}]]
  (into [] (mapcat (fn [openid-profile]
                     (reitit-routes-for-profile openid-profile no-auth-code-handler state-mismatch-handler))
                   openid-profiles)))
