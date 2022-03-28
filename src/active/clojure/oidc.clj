(ns active.clojure.oidc
  (:require [active.clojure.config :as active-config]
            [active.clojure.oidc.config :as oidc-config]
            [active.clojure.record :refer [define-record-type]]
            [clj-http.client :as http-client]
            [clj-time.core :as time]
            [clojure.string :as string]
            [crypto.random :as random]
            [ring.middleware.params :refer [wrap-params]]
            [ring.util.codec :as codec]
            [ring.util.response :as response])
  (:import [java.net URI]))

(define-record-type ^{:doc "Wraps all necessary information for a oidc identity provider profile."}
  OidcProfile
  make-oidc-profile oidc-profile?
  [name             oidc-profile-name
   authorize-uri    oidc-profile-authorize-uri
   access-token-uri oidc-profile-access-token-uri
   userinfo-uri     oidc-profile-userinfo-uri
   client-id        oidc-profile-client-id
   client-secret    oidc-profile-client-secret
   scopes           oidc-profile-scopes
   launch-uri       oidc-profile-launch-uri
   redirect-uri     oidc-profile-redirect-uri
   landing-uri      oidc-profile-landing-uri
   logout-uri       oidc-profile-logout-uri
   basic-auth?      oidc-profile-basic-auth?])

(defn make-openid-connect-uri
  [scheme host port realm endpoint]
  (if port
    (format "%s://%s:%d/auth/realms/%s/protocol/openid-connect/%s"
            scheme host port realm endpoint)
    (format "%s://%s/auth/realms/%s/protocol/openid-connect/%s"
            scheme host realm endpoint)))

(defn make-authorize-uri
  "Constructs a uri-string from the args that points to an authorize endpoint."
  [scheme host port realm]
  (make-openid-connect-uri scheme host port realm "auth"))

(defn make-token-uri
  "Constructs a uri-string from the args that points to a token endpoint."
  [scheme host port realm]
  (make-openid-connect-uri scheme host port realm "token"))

(defn make-userinfo-uri
  [scheme host port realm]
  (make-openid-connect-uri scheme host port realm "userinfo"))

(defn make-oidc-profiles
  "Takes a [[active.clojure.config/Configuration]] and extracts all
  configured [[OidcProfile]]s from the config."
  [config]
  (let [oidc-profiles-config
        (active-config/section-subconfig config oidc-config/section)]
    (mapv (fn [c]
            (let [scheme (active-config/access c oidc-config/oidc-scheme)
                  host   (active-config/access c oidc-config/oidc-host)
                  port   (active-config/access c oidc-config/oidc-port)
                  realm  (active-config/access c oidc-config/oidc-realm)
                  client (active-config/access c oidc-config/oidc-client)]
              (make-oidc-profile (active-config/access c oidc-config/oidc-name)
                                   (make-authorize-uri scheme host port realm)
                                   (make-token-uri scheme host port realm)
                                   (make-userinfo-uri scheme host port realm)
                                   (active-config/access c oidc-config/oidc-client)
                                   (active-config/access c oidc-config/oidc-client-secret)
                                   (active-config/access c oidc-config/oidc-scopes)
                                   (active-config/access c oidc-config/oidc-launch-uri)
                                   (active-config/access c oidc-config/oidc-redirect-uri)
                                   #_(active-config/access c oidc-config/oidc-landing-uri)
                                   "/"
                                   (active-config/access c oidc-config/oidc-logout-uri)
                                   (active-config/access c oidc-config/oidc-basic-auth?))))
          oidc-profiles-config)))

(defn join-scopes
  "Returns a string containing all configured [[oidc-profile-scopes]], separated by `\\space`."
  [oidc-profile]
  (string/join " " (map name (oidc-profile-scopes oidc-profile))))

(defn authorize-uri
  [oidc-profile state]
  (str (oidc-profile-authorize-uri oidc-profile)
       (if (string/includes? (oidc-profile-authorize-uri oidc-profile) "?") "&" "?")
       (let [redirect-uri (oidc-profile-redirect-uri oidc-profile)]
         (codec/form-encode (merge
                             {:response_type "code"
                              :client_id     (oidc-profile-client-id oidc-profile)
                              ;;:scope         (join-scopes oidc-profile)
                              :state         state
                              }
                             nil
                             #_(when-not (empty? redirect-uri)
                               {:redirect_uri redirect-uri}))))))

(defn- random-state
  []
  (-> (random/base64 9)
      (string/replace "+" "-")
      (string/replace "/" "_")))

(defn make-launch-handler
  [oidc-profile]
  (fn [request]
    (let [state       (random-state)
          new-session (assoc (:session request) ::authorize-state state)]
      (-> (response/redirect (authorize-uri oidc-profile state))
          (assoc :session new-session)))))

(defn coerce-to-int [n]
  (if (string? n)
    (Integer/parseInt n)
    n))

(defn format-access-token
  [{{:keys [access_token expires_in refresh_token id_token] :as body} :body}]
  (-> {:token      access_token
       :extra-data (dissoc body :access_token :expires_in :refresh_token :id_token)}
      (cond-> expires_in (assoc :expires (-> expires_in
                                             coerce-to-int
                                             time/seconds
                                             time/from-now))
              refresh_token (assoc :refresh-token refresh_token)
              id_token      (assoc :id-token id_token))))

(defn get-authorization-code
  [request]
  (get-in request [:query-params "code"]))

(defn request-params
  [oidc-profile request]
  {:grant_type   "authorization_code"
   :code         (get-authorization-code request)
   :redirect_uri (oidc-profile-redirect-uri oidc-profile)})

(defn add-header-credentials
  [options client-id client-secret]
  (assoc options :basic-auth [client-id client-secret]))

(defn add-form-credentials
  [options client-id client-secret]
  (assoc options :form-params (-> (:form-params options)
                                  (merge {:client_id     client-id
                                          :client_secret client-secret}))))

(defn get-access-token
  "For a `oidc-profile` and based on a `request` (the response of the
  idp), fetch the actual (JWT) access token.

  Might throw an exception."
  [oidc-profile request]
  (let [access-token-uri (oidc-profile-access-token-uri oidc-profile)
        client-id        (oidc-profile-client-id oidc-profile)
        client-secret    (oidc-profile-client-secret oidc-profile)
        basic-auth?      (oidc-profile-basic-auth? oidc-profile)]
    (let [resp (http-client/post access-token-uri
                                 (cond-> {:accept :json, :as :json,
                                          :form-params (request-params oidc-profile request)}
                                   basic-auth?       (add-header-credentials client-id client-secret)
                                   (not basic-auth?) (add-form-credentials client-id client-secret)))]
      (format-access-token resp))))

(defn state-matches?
  "Checks if the state given in the original request matches the
  response given by the idp."
  [request]
  (= (get-in request [:session ::authorize-state])
     (get-in request [:query-params "state"])))

(def ^:private state-mismatch-response {:status 400, :headers {}, :body "State mismatch"})
(def default-state-mismatch-handler (constantly state-mismatch-response))

(def ^:private no-auth-code-response {:status 400, :headers {}, :body "No authorization code"})
(def default-no-auth-code-handler (constantly no-auth-code-response))

(defn make-redirect-handler
  "Creates a redirect (callback) handler for a `oidc-profile`.  A
  successful login might result in an exceptional state (i.e. when the
  server cannot be reached after receiving the code.  Such errors will
  be returned as a ring-response with code 500 and the class and
  message as a Clojure-map."
  [oidc-profile no-auth-code-handler state-mismatch-handler]
  (fn [{:keys [session] :as request}]
    (cond
      (not (state-matches? request))
      (state-mismatch-handler request)

      (nil? (get-authorization-code request))
      (no-auth-code-handler request)

      :else
      (try 
        (let [access-token (get-access-token oidc-profile request)]
          (-> (response/redirect (oidc-profile-landing-uri oidc-profile))
              (assoc :session (-> session
                                  (assoc-in [::access-tokens (oidc-profile-name oidc-profile)] access-token)
                                  (dissoc ::authorize-state)))))
        (catch Exception e
          (-> (response/response {:exception (.getClass e)
                                  :message   (.getMessage e)})
              (response/status 500)
              (response/header "Content-Type" "application/json")))))))

(defn reitit-routes-for-profile
  "For a given [[OidcProfile]], returns a vector containing the launch-
  and login-callback handlers."
  [oidc-profile no-auth-code-handler state-mismatch-handler]
  [[(oidc-profile-launch-uri oidc-profile)
    {:get {:handler (make-launch-handler oidc-profile)}}]
   [(oidc-profile-redirect-uri oidc-profile)
    {:get {:handler    (make-redirect-handler oidc-profile no-auth-code-handler state-mismatch-handler)
           :middleware [[wrap-params]]}}]])

(defn reitit-routes
  "Based on a sequence of [[OidcProfile]]s, returns a vector of two
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
  `[::access-tokens <oidc-profile-name> <access-token>]`.

  2. The idp didn't provide an authorization code.  The callback
  handler returns the [[no-auth-code-response]].

  3. The state code's did not match.  The callback handle rreturns
  the [[state-mismatch-response]]."
  [oidc-profiles & [{:keys [no-auth-code-handler
                            state-mismatch-handler]
                     :or {no-auth-code-handler   default-no-auth-code-handler
                          state-mismatch-handler default-state-mismatch-handler}}]]
  (into [] (mapcat (fn [oidc-profile]
                     (reitit-routes-for-profile oidc-profile no-auth-code-handler state-mismatch-handler))
                   oidc-profiles)))
