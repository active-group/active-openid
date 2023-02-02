(ns active.clojure.openid
  (:require [active.clojure.config :as active-config]
            [active.clojure.lens :as lens]
            [active.clojure.openid :as openid]
            [active.clojure.openid.config :as openid-config]
            [active.clojure.record :refer [define-record-type]]
            [active.clojure.logger.event :as log]
            [clj-http.client :as http-client]
            [clj-time.core :as time]
            [clj-time.coerce :as time-coerce]
            [camel-snake-kebab.core :as csk]
            [clojure.data.json :as json]
            [clojure.string :as string]
            [crypto.random :as random]
            [hiccup.page :as hp]
            [ring.util.codec :as codec]
            [ring.util.response :as response]
            [ring.middleware.defaults :as ring-defaults]
            [ring.middleware.session :as ring-session]
            [ring.middleware.session.memory :as ring-session-memory]))

(define-record-type OpenidProviderConfig
  {:projection-lens openid-provider-config-projection-lens}
  make-openid-provider-config openid-provider-config?
  [authorize-endpoint     openid-provider-config-authorize-endpoint
   token-endpoint         openid-provider-config-token-endpoint
   userinfo-endpoint      openid-provider-config-userinfo-endpoint
   end-session-endpoint   openid-provider-config-end-session-endpoint
   check-session-endpoint openid-provider-config-check-session-endpoint
   supports-backchannel-logout? openid-provider-config-supports-backchannel-logout?])

(def openid-provider-config-lens
  (openid-provider-config-projection-lens :authorization-endpoint
                                          :token-endpoint
                                          :userinfo-endpoint
                                          :end-session-endpoint
                                          :check-session-endpoint
                                          :supports-backchannel-logout?))

(define-record-type ^{:doc "Wraps all necessary information for a openid identity provider profile."}
  OpenidProfile
  {:projection-lens openid-profile-projection-lens}
  make-openid-profile openid-profile?
  [name                   openid-profile-name
   provider-config        openid-profile-openid-provider-config
   client-id              openid-profile-client-id
   client-secret          openid-profile-client-secret
   scopes                 openid-profile-scopes
   base-uri               openid-profile-base-uri])

(def openid-profile-lens
  (openid-profile-projection-lens :name
                                  (lens/>> :provider-config openid-provider-config-lens)
                                  :client-id
                                  :client-secret
                                  :scopes
                                  :base-uri))

(define-record-type OpenidInstanceNotAvailable
  make-openid-instance-not-available openid-instance-not-available?
  [name openid-instance-not-available-name
   tried-endpoint openid-instance-not-available-tried-instance
   error-msg openid-instance-not-available-error-msg])

(define-record-type AccessToken
  {:projection-lens access-token-projection-lens}
  make-access-token
  access-token?
  [token access-token-token
   type access-token-type
   refresh-token access-token-refresh-token
   id-token access-token-id-token
   expires access-token-expires
   extra-data access-token-extra-data])

(def access-token-lens
  (access-token-projection-lens :token :type :refresh-token :id-token
                                (lens/>> :expires (lens/xmap time-coerce/to-long time-coerce/from-long))
                                :extra-data))

(define-record-type UserInfo
  {:projection-lens user-info-projection-lens}
  make-user-info
  user-info?
  [username user-info-username
   name user-info-name
   email user-info-email
   rest user-info-rest
   openid-profile user-info-openid-profile
   logout-uri user-info-logout-uri
   access-token user-info-access-token])

(def user-info-lens
  (user-info-projection-lens :username :name :email
                             :rest
                             (lens/>> :openid-profile openid-profile-lens)
                             :logout-uri
                             (lens/>> :access-token access-token-lens)))

(defn get-openid-provider-config!
  ;; Based on the connection parameters, fetches the openid provider
  ;; configuration from the .well-known json object provided by the idp.

  ;; Also see [here](https://ldapwiki.com/wiki/Openid-configuration).

  ;; If the openid instance is not available, returns
  ;; an [[%openid-instance-not-available]]] condition.
  [provider-name provider-config-uri]
  (log/log-event! :trace (log/log-msg "Requesting openid provider config for" provider-name "from" provider-config-uri))
  (try (let [{:keys [status body]} (http-client/get provider-config-uri {:throw-exceptions false})]
         (log/log-event! :trace (log/log-msg "Received reply from" provider-config-uri ":" status body))
         (case status
           200 (let [provider-config-edn (json/read-str body :key-fn csk/->kebab-case-keyword)]
                 (log/log-event! :debug (log/log-msg "Received provider config:" provider-config-edn))
                 (openid-provider-config-lens provider-config-edn))
           (make-openid-instance-not-available provider-name provider-config-uri (str status " " body))))
       (catch Exception e
         (log/log-exception-event! :error (log/log-msg "Received exception from" provider-config-uri ":" (.getMessage e)) e)
         (make-openid-instance-not-available provider-name provider-config-uri (.getMessage e)))))

(defn make-openid-profile!
  "See make-openid-profiles!"
  [openid-config]
  (let [provider-name (active-config/access openid-config openid-config/openid-provider-name openid-config/openid-provider-section)
        provider-config-uri (active-config/access openid-config openid-config/openid-provider-config-uri openid-config/openid-provider-section)
        ;; This might fail Also, this might be a bad idea:
        ;; TODO If the identity provider is unavailable at
        ;; startup, there is no recovery.
        provider-config-or-error
        (get-openid-provider-config! provider-name provider-config-uri)]
    (cond
      (openid-provider-config? provider-config-or-error)
      (make-openid-profile provider-name
                           provider-config-or-error
                           (active-config/access openid-config openid-config/openid-client-id openid-config/openid-client-section)
                           (active-config/access openid-config openid-config/openid-client-secret openid-config/openid-client-section)
                           (active-config/access openid-config openid-config/openid-client-scopes openid-config/openid-client-section)
                           (active-config/access openid-config openid-config/openid-client-base-uri openid-config/openid-client-section))

      (openid-instance-not-available? provider-config-or-error)
      provider-config-or-error)))

(defn make-openid-profiles!
  "Takes a [[active.clojure.config/Configuration]] and extracts all
  configured [[OpenidProfile]]s from the config.

  If any openid instance is not available, returns
  an [[%openid-instance-not-available]]] condition instead of
  an [[OpenidProfile]] for that instance.."
  [config]
  (mapv make-openid-profile! (active-config/section-subconfig config openid-config/openid-profiles-section)))

;; logins

(define-record-type Logins
  make-logins
  logins?
  [state-profile-map logins-state-profile-map
   availables logins-availables
   unavailables logins-unavailables])

(define-record-type AvailableLogin
  make-available-login
  available-login?
  [uri available-login-uri
   name available-login-name])

(define-record-type UnavailableLogin
  make-unavailable-login
  unavailable-login?
  [name unavailable-login-name
   error unavailable-login-error])

(defn absolute-redirect-uri
  "Returns the qualified redirect-uri of an `openid-profile`."
  [openid-profile & [uri]]
  (str (openid-profile-base-uri openid-profile) uri))

(defn join-scopes
  ;; Returns a string containing all configured
  ;; [[openid-profile-scopes]], separated by `\space`.
  [openid-profile]
  (string/join " " (map name (openid-profile-scopes openid-profile))))

(defn authorize-uri
  [openid-profile state redirect-uri]
  (let [authorize-uri (lens/yank openid-profile (lens/>> openid-profile-openid-provider-config
                                                         openid-provider-config-authorize-endpoint))]
    (str authorize-uri
         (if (string/includes? authorize-uri "?") "&" "?")
         (codec/form-encode {:response_type "code"
                             :client_id     (openid-profile-client-id openid-profile)
                             :redirect_uri  (absolute-redirect-uri openid-profile redirect-uri)
                             :state         state
                             :scope         (join-scopes openid-profile)}))))

(defn random-state
  []
  (-> (random/base64 9)
      (string/replace "+" "-")
      (string/replace "/" "_")))

(defn logins-from-config!
  [config redirect-uri]
  (let [openid-profiles (make-openid-profiles! config)
        available-profiles (filter openid-profile? openid-profiles)
        unavailable-profiles (remove openid-profile? openid-profiles)
        state-profile-map (into {} (mapv (fn [openid-profile]
                                           [(random-state) (openid-profile-lens {} openid-profile)])
                                         available-profiles))]
    (make-logins (if (empty? state-profile-map) nil state-profile-map)
                 (mapv (fn [[state _openid-profile-edn] openid-profile]
                         (make-available-login (authorize-uri openid-profile state redirect-uri)
                                               (openid-profile-name openid-profile)))
                       state-profile-map available-profiles)
                 (mapv (fn [openid-instance-not-available] (make-unavailable-login (openid-instance-not-available-name openid-instance-not-available)
                                                                                   (openid-instance-not-available-error-msg openid-instance-not-available)))
                       unavailable-profiles))))

;; post access token

(defn coerce-to-int [n]
  (if (string? n)
    (Integer/parseInt n)
    n))

(defn parse-params
  [request]
  (if-let [query-string (:query-string request)]
    (codec/form-decode query-string)
    {}))

(defn get-authorization-code
  [request]
  (get (parse-params request) "code"))

(defn get-session-state
  [request]
  (get (parse-params request) "state"))

(defn add-form-credentials
  [options client-id client-secret]
  (assoc options :form-params (-> (:form-params options)
                                  (merge {:client_id     client-id
                                          :client_secret client-secret}))))

(define-record-type NoAccessToken
  make-no-access-token
  no-access-token?
  [error-message no-access-token-error-message])

(defn format-access-token
  [{:keys [access-token token-type expires-in refresh-token id-token] :as body}]
  (make-access-token access-token
                     token-type
                     refresh-token
                     id-token
                     (-> expires-in
                         coerce-to-int
                         time/seconds
                         time/from-now)
                     (dissoc body :access-token :token-type :expires-in :refresh-token :id-token)))

(defn fetch-access-token!
  "For a `openid-profile` and based on a `request` (the response of the
  idp), fetch the actual (JWT) access token.

  Might throw an exception."
  [openid-profile authorization-code redirect-uri]
  (let [access-token-uri (lens/yank openid-profile (lens/>> openid-profile-openid-provider-config
                                                            openid-provider-config-token-endpoint))
        client-id        (openid-profile-client-id openid-profile)
        client-secret    (openid-profile-client-secret openid-profile)
        payload          (add-form-credentials {:form-params {:grant_type   "authorization_code"
                                                              :code         authorization-code
                                                              :redirect_uri (absolute-redirect-uri openid-profile redirect-uri)}}
                                               client-id client-secret)]
    (log/log-event! :trace (log/log-msg "Requesting access token from" access-token-uri "with payload" payload))

    (try (let [{:keys [status body]} (http-client/post access-token-uri payload {:throw-exceptions false})]
           (log/log-event! :trace (log/log-msg "Received reply from" access-token-uri ":" status body))
           (case status
             200 (let [access-token-edn (json/read-str body :key-fn csk/->kebab-case-keyword)]
                   (log/log-event! :debug (log/log-msg "Received access-token" access-token-edn))
                   (format-access-token access-token-edn))
             (make-no-access-token (str status " " body))))
         (catch Exception e
           (log/log-exception-event! :error (log/log-msg "Received exception from" access-token-uri ":" (.getMessage e)) e)
           (make-no-access-token (.getMessage e))))))

;; default handler for middleware

(defn default-error-handler
  [request error-string original-uri & [exception]]
  {:status 500
   :headers {"Content-Type" "text/html"}
   :body
   (hp/html5
    [:head [:meta {:charset "UTF-8"}]]
    [:body
     [:main
      [:div
       [:h1 "Error:"]
       [:div [:code error-string]]
       [:div (when original-uri [:a {:href original-uri} "try again"])]
       [:h1 "Session:"]
       [:div [:code (:session request)]]
       [:h1 "Exception:"]
       (when exception
         [:div [:code (pr-str exception)]])]]])})

(defn render-available-login
  [available-login]
  [:a {:href (available-login-uri available-login)}
   (available-login-name available-login)])

(defn render-unavailable-login
  [unavailable-login]
  [:span (unavailable-login-name unavailable-login)
   (str "(" (unavailable-login-error unavailable-login) ")")])

(defn default-login-handler
  [_req availables unavailables]
  (let [resp {:status 200
              :headers {"Content-Type" "text/html"}
              :body
              (hp/html5
               [:head [:meta {:charset "UTF-8"}]]
               [:body
                [:main
                 [:div
                  [:h1 "Login:"]
                  [:h2 "available identity providers:"]
                  [:ul (for [x (mapv render-available-login availables)]
                         [:li x])]
                  [:h2 "unavailable identity providers:"]
                  [:ul (for [x (mapv render-unavailable-login unavailables)]
                         [:li x])]]]])}]
    resp))

(def default-logout-endpoint "/logout")

(defn default-logout-handler
  [_request]
  (response/redirect "/"))

(defn logout-uri
  [openid-profile id-token-hint logout-endpoint]
  (let [end-session-endpoint
        (lens/yank openid-profile (lens/>> openid-profile-openid-provider-config
                                           openid-provider-config-end-session-endpoint))]
    (str end-session-endpoint
         "?"
         (codec/form-encode {:post_logout_redirect_uri (absolute-redirect-uri openid-profile logout-endpoint)
                             :id_token_hint            id-token-hint}))))

(def state
  (lens/>> :session ::auth-state))

(define-record-type Authenticated
  authenticated
  authenticated?
  [user-info authenticated-user-info])

(defn authenticated-request?
  [request]
  (authenticated? (state request)))

(define-record-type AuthenticationStarted
  authentication-started
  authentication-started?
  [state-profile-map authentication-started-state-profile-map
   original-uri authentication-started-original-uri])

(defn authentication-started-request?
  [request]
  (authentication-started? (state request)))

(define-record-type Unauthenticated
  unauthenticated
  unauthenticated?
  [])

(defn unauthenticated-request?
  [request]
  (or (nil? (state request))
      (unauthenticated? (state request))
      #_(and (authentication-started? (state request))
           (nil? (get-session-state request)))))

(define-record-type NoUserInfo
  make-no-user-info
  no-user-info?
  [error-message no-user-info-error-message])

(defn fetch-user-info
  [openid-profile access-token logout-endpoint]
  (let [token (access-token-token access-token)
        token-type (access-token-type access-token)
        id-token (access-token-id-token access-token)]
    (when token
      (let [user-info-uri (lens/yank openid-profile (lens/>> openid/openid-profile-openid-provider-config
                                                             openid/openid-provider-config-userinfo-endpoint))
            payload       {:headers {:authorization (str token-type " " token)}}]
        (log/log-event! :trace (log/log-msg "Requesting user info from" user-info-uri "with payload" payload))
        (try
          (let [{:keys [status body]} (http-client/get user-info-uri payload)]
            (log/log-event! :trace (log/log-msg "Received response from " user-info-uri ":" status body))
            (case status
              200 (let [user-data-edn (json/read-str body :key-fn csk/->kebab-case-keyword)]
                    (log/log-event! :debug (log/log-msg "Received user info:" user-data-edn))
                    (make-user-info (:preferred-username user-data-edn)
                                    (:name user-data-edn)
                                    (:email user-data-edn)
                                    user-data-edn
                                    openid-profile
                                    (logout-uri openid-profile id-token logout-endpoint)
                                    access-token))
              (make-no-user-info (str status " " body))))
          (catch Exception e
            (log/log-exception-event! :error (log/log-msg "Received exception from" user-info-uri ":" (.getMessage e)) e)
            (make-no-user-info (.getMessage e))))))))

(defn wrap-openid-authentication*
  "Middleware that shortcuts execution of the `handler` and redirects the user
  to the login page.

  It also takes care of the openid authentication process states `unauthenticated`,
  `authentication started`, `authenticated`.

  The state `authentication started` is the most complicated one: There, the
  middleware tries to obtain tokens and user data from the IDP and needs to
  validate the data.

  - `:login-handler`: Handler that the middleware calls if currently
  unauthenticated.  The login handler should display links to IDPs to start the
  authentication process.  The login handler gets called with three arguments:
     - `request`: The current request
     - `availables`: List of [[Available]] IDPs
     - `unavailables`: List of [[Unavailable]] IDPs
  If not `:login-handler` is given, it defaults to [[default-login-handler]].

  - `:logout-endpoint`: The endpoint for the IDP to redirect to after
  user-initated logout.  This is needed to remove the auth information from the
  session.  Defaults to [[default-logout-endpoint]].

  - `:logout-handler`: The handler for the logout endpoint above.  It gets
  called with `request`.  Defaults to [[default-logout-handler]] which redirects
  to `/`.

  - `:error-handler`: Handler thet the middleware calls in case of some
  unexpected error.  The error handler gets called with these arguments:
     - `request`: The current request
     - `error-string`: A string that describes the error
     - `original-uri`: The URI of the original request, useful to try request
       again
     - and optionally an `exception`
  Defaults to [[default-error-handler]].
  "
  [config & {:keys [login-handler
                    logout-endpoint
                    logout-handler
                    error-handler]
             :or   {login-handler   default-login-handler
                    logout-endpoint default-logout-endpoint
                    logout-handler   default-logout-handler
                    error-handler   default-error-handler}}]
  (fn [handler]
    (fn [request]
      (log/log-event! :trace (log/log-msg "wrap-ensure-authenticated: request" request))
      (try
        (cond
          (re-matches (re-pattern (str "^" logout-endpoint)) (or (:uri request) ""))
          (do
            (log/log-event! :debug (log/log-msg "wrap-ensure-authenticated: logout-endpoint, removing stored credentials"))
            (-> (logout-handler request)
                (state (unauthenticated))))

          (unauthenticated-request? request)
          (do
            (log/log-event! :debug (log/log-msg "wrap-ensure-authenticated: unauthenticated" (pr-str (state request))))
            (let [original-uri (:uri request)
                  logins (logins-from-config! config original-uri)]
              (log/log-event! :trace (log/log-msg "wrap-ensure-authenticated: unauthenticated, calling login handler for" (pr-str logins)))
              (-> (login-handler request (logins-availables logins) (logins-unavailables logins))
                  (state (authentication-started (logins-state-profile-map logins) original-uri)))))

          ;; this is the request that comes from the IDP
          (authentication-started-request? request)
          (do
            (log/log-event! :debug (log/log-msg "wrap-ensure-authenticated: authentication-started" (pr-str (state request))))
            (let [state-from-idp (get-session-state request)
                  _ (log/log-event! :trace (log/log-msg "wrap-ensure-authenticated: authentication started, got state from IDP" state-from-idp))
                  authentication-started (state request)
                  original-uri (authentication-started-original-uri authentication-started)
                  _ (log/log-event! :trace (log/log-msg "wrap-ensure-authenticated: authentication started, found original uri" original-uri))
                  state-profile-map (authentication-started-state-profile-map authentication-started)
                  _ (log/log-event! :trace (log/log-msg "wrap-ensure-authenticated: authentication started, found state-profile-edn" state-profile-map))
                  openid-profile-edn (get state-profile-map state-from-idp)
                  _ (log/log-event! :trace (log/log-msg "wrap-ensure-authenticated: authentication started, trying to authorize with profile" openid-profile-edn))]
              (cond
                (nil? openid-profile-edn)
                (-> (error-handler request "The state we got from IDP did not match our's." original-uri)
                    (state (unauthenticated)))

                (nil? (get-authorization-code request))
                (-> (error-handler request "The authorization code from the IDP is missing." original-uri)
                    (state (unauthenticated)))

                :else
                (let [openid-profile (openid-profile-lens openid-profile-edn)
                      access-token (fetch-access-token! openid-profile (get-authorization-code request) original-uri)]
                  (if (no-access-token? access-token)
                    (-> (error-handler request (str "Got no access token - " (no-access-token-error-message access-token)) original-uri)
                        (state (unauthenticated)))
                    (do
                      (log/log-event! :trace (log/log-msg "wrap-ensure-authenticated: got access-token" (pr-str access-token)))
                      (let [user-info (fetch-user-info openid-profile access-token logout-endpoint)]
                        (if (no-user-info? user-info)
                          (-> (error-handler request (str "Got no user info - " (no-user-info-error-message user-info)) original-uri)
                              (state (unauthenticated)))

                          (do
                            (log/log-event! :trace (log/log-msg "wrap-ensure-authenticated: got user-info" (pr-str user-info)))
                            (let [user-info-edn (user-info-lens {} user-info)]
                              (log/log-event! :info (log/log-msg "Successfully logged in user" (user-info-username user-info)))
                              (-> (response/redirect original-uri)
                                  (state (authenticated user-info-edn)))))))))))))

          (authenticated-request? request)
          ;; FIXME: consider validity here, maybe refresh token https://auth0.com/docs/authenticate/login/oidc-conformant-authentication/oidc-adoption-refresh-tokens
          (do
            (log/log-event! :debug (log/log-msg "wrap-ensure-authenticated: already authenticated " (pr-str (state request)) ", handling request" request))
            (handler request)))
        (catch Exception e
          (log/log-exception-event! :error (log/log-msg "wrap-ensure-authenticated: caught exception" (.getMessage e) request) e)
          (error-handler request (.getMessage e) e))))))

(defn wrap-openid-session
  "Our implementation uses sessions, so we need [[ring-session/wrap-session]] middleware.
  This is a convenience wrapper around [[ring-session/wrap-session]] that sets
  some useful defaults and optionally accepts and uses a given `session-store`."
  [handler & [session-store]]
  (let [session-store  (or session-store (ring-session-memory/memory-store))
        session-config (-> (:session ring-defaults/site-defaults)
                           (assoc :store session-store)
                           (assoc :cookie-name "active-openid-session")
                           (assoc-in [:cookie-attrs :same-site] :lax))]
    (-> handler
        (ring-session/wrap-session session-config))))

(defn wrap-openid-authentication
  "Convenience middleware stack for OpenID authentication that combines all
  other middlewares that its implementation depends on.

  Currently, this is [[ring-session/wrap-session]].  To avoid having more than
  one instance of the `session-store`, you have three options:

  - Use optional argument `:session-store` to pass in your global session store.

  - Bind one instance of this middleware to a variable and use the variable if
    you need this middleware in different places.

  - Put your own [[ring-session/wrap-session]] in your middleware stack and use
    [[wrap-openid-authentication*]] instead of this middleware.

  See [[wrap-openid-authentication*]] for OpenID-specific documentation and
  options."
  [config & {:keys [session-store] :as args}]
  (let [wrap-openid-auth (wrap-openid-authentication* config args)]
    (fn [handler] ;; FIXME: add & args to the parameter-list here, because of reitit
      (-> handler
          wrap-openid-auth
          (wrap-openid-session session-store)))))

(defn user-info-from-request
  "Retrieve [[UserInfo]] for logged in user from `request`.
  Use this function in your handler to obtain information about your user."
  [request]
  (let [state (state request)
        user-info-edn (and (authenticated? state) (authenticated-user-info state))]
    (if user-info-edn
      (user-info-lens user-info-edn)
      nil)))
