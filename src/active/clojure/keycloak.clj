(ns active.clojure.keycloak
  (:require [active.clojure.condition :as condition]
            [active.clojure.config :as active-config]
            [active.clojure.config :as config]
            [active.clojure.lens :as lens]
            [active.clojure.keycloak :as keycloak]
            [active.clojure.keycloak.config :as keycloak-config]
            [active.clojure.record :refer [define-record-type]]
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

(define-record-type ^{:doc "Wraps all necessary information for a keycloak identity provider profile."}
  KeycloakProfile
  make-keycloak-profile keycloak-profile?
  [name                   keycloak-profile-name
   openid-provider-config keycloak-profile-openid-provider-config
   client-id              keycloak-profile-client-id
   client-secret          keycloak-profile-client-secret
   scopes                 keycloak-profile-scopes
   launch-uri             keycloak-profile-launch-uri
   redirect-uri           keycloak-profile-redirect-uri
   landing-uri            keycloak-profile-landing-uri
   logout-uri             keycloak-profile-logout-uri
   backchannel-logout-uri keycloak-profile-backchannel-logout-uri
   basic-auth?            keycloak-profile-basic-auth?])

(defn get-openid-configuration-url
  [scheme host port realm]
  (format "%s://%s:%d/auth/realms/%s/.well-known/openid-configuration" scheme host port realm))

(defn- keycloak-supports-backchannel-logout?
  ;; True if the `keycloak-profile` supports backchannel logouts as discovered
  ;; on the .well-known page.
  [keycloak-profile]
  (lens/yank keycloak-profile (lens/>> keycloak-profile-openid-provider-config
                                   openid-provider-config-supports-backchannel-logout?)))

(define-record-type KeycloakInstanceNotAvailable
  make-keycloak-instance-not-available keycloak-instance-not-available?
  [tried-endpoint keycloak-instance-not-available-tried-instance
   error-msg keycloak-instance-not-available-error-msg])

(defn- get-openid-provider-config!
  ;; Based on the connection parameters, fetches the openid provider
  ;; configuration from the .well-known json object provided by the idp.

  ;; Also see [here](https://ldapwiki.com/wiki/Openid-configuration).

  ;; If the keycloak instance is not available, returns
  ;; an [[%keycloak-instance-not-available]]] condition.
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
           (make-keycloak-instance-not-available configuration-url (.getMessage e))))))

(defn make-keycloak-profiles!
  "Takes a [[active.clojure.config/Configuration]] and extracts all
  configured [[KeycloakProfile]]s from the config.

  If any keycloak instance is not available, returns
  an [[%keycloak-instance-not-available]]] condition instead of
  an [[KeycloakProfile]] for that instance.."
  [config]
  (let [keycloak-profiles-config (active-config/section-subconfig config keycloak-config/section)]
    (mapv (fn [c]
            (let [scheme (active-config/access c keycloak-config/keycloak-scheme)
                  host   (active-config/access c keycloak-config/keycloak-host)
                  port   (active-config/access c keycloak-config/keycloak-port)
                  realm  (active-config/access c keycloak-config/keycloak-realm)
                  client (active-config/access c keycloak-config/keycloak-client)

                  ;; This might fail Also, this might be a bad idea:
                  ;; TODO If the identity provider is unavailable at
                  ;; startup, there is no recovery.
                  openid-provider-config-or-error
                  (get-openid-provider-config! scheme host port realm)]
              (cond
                (openid-provider-config? openid-provider-config-or-error)
                (make-keycloak-profile (active-config/access c keycloak-config/keycloak-name)
                                   openid-provider-config-or-error
                                   (active-config/access c keycloak-config/keycloak-client)
                                   (active-config/access c keycloak-config/keycloak-client-secret)
                                   (active-config/access c keycloak-config/keycloak-scopes)
                                   (active-config/access c keycloak-config/keycloak-launch-uri)
                                   (active-config/access c keycloak-config/keycloak-redirect-uri)
                                   (active-config/access c keycloak-config/keycloak-landing-uri)
                                   (active-config/access c keycloak-config/keycloak-logout-uri)
                                   (active-config/access c keycloak-config/keycloak-backchannel-logout-uri)
                                   (active-config/access c keycloak-config/keycloak-basic-auth?))

                (keycloak-instance-not-available? openid-provider-config-or-error)
                openid-provider-config-or-error)))
          keycloak-profiles-config)))

(defn- join-scopes
  ;; Returns a string containing all configured
  ;; [[keycloak-profile-scopes]], separated by `\space`.
  [keycloak-profile]
  (string/join " " (map name (keycloak-profile-scopes keycloak-profile))))

(defn- authorize-uri
  [keycloak-profile state]
  (let [authorize-uri (lens/yank keycloak-profile (lens/>> keycloak-profile-openid-provider-config
                                                       openid-provider-config-authorize-endpoint))]
    (str authorize-uri
         (if (string/includes? authorize-uri "?") "&" "?")
         (let [redirect-uri (keycloak-profile-redirect-uri keycloak-profile)]
           (codec/form-encode {:response_type "code"
                               :client_id     (keycloak-profile-client-id keycloak-profile)
                               :redirect_uri  (keycloak-profile-redirect-uri keycloak-profile)
                               :state         state})))))

(defn- random-state
  []
  (-> (random/base64 9)
      (string/replace "+" "-")
      (string/replace "/" "_")))

(defn- make-launch-handler
  [keycloak-profile]
  (fn [request]
    (let [state       (random-state)
          new-session (assoc (:session request) ::authorize-state state)]
      (-> (response/redirect (authorize-uri keycloak-profile state))
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
  [keycloak-profile request]
  {:grant_type   "authorization_code"
   :code         (get-authorization-code request)
   :redirect_uri (keycloak-profile-redirect-uri keycloak-profile)})

(defn- add-header-credentials
  [options client-id client-secret]
  (assoc options :basic-auth [client-id client-secret]))

(defn- add-form-credentials
  [options client-id client-secret]
  (assoc options :form-params (-> (:form-params options)
                                  (merge {:client_id     client-id
                                          :client_secret client-secret}))))

(defn- get-access-token
  "For a `keycloak-profile` and based on a `request` (the response of the
  idp), fetch the actual (JWT) access token.

  Might throw an exception."
  [keycloak-profile request]
  (let [access-token-uri (lens/yank keycloak-profile (lens/>> keycloak-profile-openid-provider-config
                                                          openid-provider-config-token-endpoint))
        client-id        (keycloak-profile-client-id keycloak-profile)
        client-secret    (keycloak-profile-client-secret keycloak-profile)
        basic-auth?      (keycloak-profile-basic-auth? keycloak-profile)]
    (let [resp (http-client/post access-token-uri
                                 (cond-> {:accept :json, :as :json,
                                          :form-params (request-params keycloak-profile request)}
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
(def ^:private default-state-mismatch-handler (constantly state-mismatch-response))

(def ^:private no-auth-code-response {:status 400, :headers {}, :body "No authorization code"})
(def ^:private default-no-auth-code-handler (constantly no-auth-code-response))

(defn- make-redirect-handler
  ;; Creates a redirect (callback) handler for a `keycloak-profile`.  A
  ;; successful login might result in an exceptional state (i.e. when
  ;; the server cannot be reached after receiving the code.  Such
  ;; errors will be returned as a ring-response with code 500 and the
  ;; class and message as a Clojure-map.
  [keycloak-profile no-auth-code-handler state-mismatch-handler]
  (fn [{:keys [session] :as request}]
    (cond
      (not (state-matches? request))
      (state-mismatch-handler request)

      (nil? (get-authorization-code request))
      (no-auth-code-handler request)

      :else
      (try 
        (let [access-token (get-access-token keycloak-profile request)
              resp (-> (response/redirect (keycloak-profile-landing-uri keycloak-profile))
                       (assoc :session (-> session
                                           (assoc-in [::access-tokens (keycloak-profile-name keycloak-profile)] access-token)
                                           (dissoc ::authorize-state))))]
          resp)
        (catch Exception e
          (-> (response/response {:exception (.getClass e)
                                  :message   (.getMessage e)})
              (response/status 500)
              (response/header "Content-Type" "application/json")))))))

(defn- make-user-session-destroyer
  [keycloak-profile]
  (fn [req]
    (update-in req [:session ::access-tokens] dissoc (keycloak-profile-name keycloak-profile))))

(defn keycloak-logout
  "Function that performs a logout at the idp for the current user.
  Clears the whole :session for the `keycloak-profile`."
  [keycloak-profile]
  (let [end-session-endpoint
        (lens/yank keycloak-profile (lens/>> keycloak-profile-openid-provider-config
                                         openid-provider-config-end-session-endpoint))
        destroy-user-session (make-user-session-destroyer keycloak-profile)]
    (-> (response/redirect
         (str end-session-endpoint
              "?"
              (codec/form-encode {:post_logout_redirect_uri (str "http://localhost:1414"
                                                                 (keycloak-profile-landing-uri keycloak-profile))})))
        destroy-user-session)))

(defn make-backchannel-logout-handler
  [keycloak-profile]
  (fn [req]
    (println "backchannel-logout-handler" req)
    ((make-user-session-destroyer keycloak-profile) req)))

(defn reitit-routes-for-profile
  "For a given [[KeycloakProfile]], returns a vector containing the launch-
  and login-callback handlers."
  [keycloak-profile no-auth-code-handler state-mismatch-handler]
  (->> (concat [[(keycloak-profile-launch-uri keycloak-profile)
                 {:get {:handler (make-launch-handler keycloak-profile)}}]
                [(keycloak-profile-redirect-uri keycloak-profile)
                 {:get {:handler    (make-redirect-handler keycloak-profile no-auth-code-handler state-mismatch-handler)
                        :middleware [[wrap-params]]}}]]
               (when (keycloak-supports-backchannel-logout? keycloak-profile)
                 [[(keycloak-profile-logout-uri keycloak-profile)
                   {:post {:handler    (make-backchannel-logout-handler keycloak-profile)
                           :middleware [[wrap-params]]}}]]))
       (into [])))

(defn reitit-routes
  "Based on a sequence of [[KeycloakProfile]]s, returns a vector of two
  reitit routes that handle the initial login launch and the keycloak
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
  `[::access-tokens <keycloak-profile-name> <access-token>]`.

  2. The idp didn't provide an authorization code.  The callback
  handler returns the [[no-auth-code-response]].

  3. The state code's did not match.  The callback handle rreturns
  the [[state-mismatch-response]]."
  [keycloak-profiles & [{:keys [no-auth-code-handler
                            state-mismatch-handler]
                     :or   {no-auth-code-handler   default-no-auth-code-handler
                            state-mismatch-handler default-state-mismatch-handler}}]]
  (into [] (mapcat (fn [keycloak-profile]
                     (reitit-routes-for-profile keycloak-profile no-auth-code-handler state-mismatch-handler))
                   keycloak-profiles)))
