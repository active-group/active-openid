(ns active.clojure.openid
  (:require [active.clojure.config :as active-config]
            [active.clojure.lens :as lens]
            [active.clojure.openid.config :as openid-config]
            [active.clojure.record :refer [define-record-type]]
            [active.clojure.logger.event :as log]
            [clj-http.client :as http-client]
            [clj-jwt.core :as jwt]
            [clj-time.core :as time]
            [clj-time.coerce :as time-coerce]
            [camel-snake-kebab.core :as csk]
            [clojure.data.json :as json]
            [clojure.string :as string]
            [crypto.random :as random]
            [hiccup.page :as hp]
            [hiccup.form :as hf]
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

(def ^:private openid-provider-config-lens
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
   base-uri               openid-profile-base-uri
   user-info-from         openid-profile-user-info-from
   http-client-opts-map   openid-profile-http-client-opts-map])

(def ^:private openid-profile-lens
  (openid-profile-projection-lens :name
                                  (lens/>> :provider-config openid-provider-config-lens)
                                  :client-id
                                  :client-secret
                                  :scopes
                                  :base-uri
                                  :user-info-from
                                  :http-client-opts-map))

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

(def ^:private access-token-lens
  (access-token-projection-lens :token :type :refresh-token :id-token
                                (lens/>> :expires (lens/xmap time-coerce/to-long time-coerce/from-long))
                                :extra-data))

(define-record-type
  ^{:doc "All the informationen needed to render either a logout link or a logout form."}
  UserLogoutInfo
  {:projection-lens user-logout-info-projection-lens}
  really-make-user-logout-info
  user-logout-info?
  [uri user-logout-info-uri
   params-map user-logout-info-params-map])

(def ^:private user-logout-info-lens
  (user-logout-info-projection-lens :uri :params-map))

(define-record-type UserInfo
  {:projection-lens user-info-projection-lens}
  make-user-info
  user-info?
  [^{:doc "The user ID the user is known to the IDP. Maybe nil."}
   id user-info-id
   ^{:doc "The display name of the user, at least firstname and lastname. Maybe nil."}
   name user-info-name
   ^{:doc "The email address of the user. Maybe nil."}
   email user-info-email
   ^{:doc "The groups the user is a member of. Maybe nil."}
   groups user-info-groups
   ^{:doc "The rest of the claims obtained from the IDP. Maybe nil."}
   claims user-info-claims
   ^{:doc "The configured profile of the IDP which that this data got obtained."}
   openid-profile user-info-openid-profile
   ^{:doc "The information needed to logout the user, see [[UserLogoutInfo]]."}
   logout-info user-info-logout-info
   ^{:doc "The raw access token from the IDP."}
   access-token user-info-access-token])

(def ^:private user-info-lens
  (user-info-projection-lens :id :name :email :groups
                             :rest
                             (lens/>> :openid-profile openid-profile-lens)
                             (lens/>> :logout-info user-logout-info-lens)
                             (lens/>> :access-token access-token-lens)))

(def ^:private default-http-client-opts
  {:throw-exceptions false
   :insecure? true})

(defn get-openid-provider-config!
  ;; Based on the connection parameters, fetches the openid provider
  ;; configuration from the .well-known json object provided by the idp.

  ;; Also see [here](https://ldapwiki.com/wiki/Openid-configuration).

  ;; If the openid instance is not available, returns
  ;; an [[%openid-instance-not-available]]] condition.
  [provider-name provider-config-uri http-client-opts-map]
  (log/log-event! :trace (log/log-msg "Requesting openid provider config for" provider-name "from" provider-config-uri (when http-client-opts-map (str "with " http-client-opts-map))))
  (try (let [{:keys [status body]} (http-client/get provider-config-uri (merge default-http-client-opts http-client-opts-map))]
         (log/log-event! :trace (log/log-msg "Received reply from" provider-config-uri ":" status body))
         (case status
           200 (let [provider-config-edn (json/read-str body :key-fn csk/->kebab-case-keyword)]
                 (log/log-event! :debug (log/log-msg "Received provider config:" provider-config-edn))
                 (openid-provider-config-lens provider-config-edn))
           (make-openid-instance-not-available provider-name provider-config-uri (str status " " body))))
       (catch Exception e
         (log/log-exception-event! :error (log/log-msg "Received exception from" provider-config-uri ":" (.getMessage e)) e)
         (make-openid-instance-not-available provider-name provider-config-uri (.getMessage e)))))

(defn- make-openid-profile!
  "See make-openid-profiles!"
  [openid-config]
  (let [provider-name (active-config/access openid-config openid-config/openid-provider-name openid-config/openid-provider-section)
        provider-config-uri (active-config/access openid-config openid-config/openid-provider-config-uri openid-config/openid-provider-section)
        http-client-opts-map (active-config/access openid-config openid-config/openid-proxy-section)
        ;; This might fail Also, this might be a bad idea:
        ;; TODO If the identity provider is unavailable at
        ;; startup, there is no recovery.
        provider-config-or-error
        (get-openid-provider-config! provider-name provider-config-uri http-client-opts-map)]
    (cond
      (openid-provider-config? provider-config-or-error)
      (make-openid-profile provider-name
                           provider-config-or-error
                           (active-config/access openid-config openid-config/openid-client-id openid-config/openid-client-section)
                           (active-config/access openid-config openid-config/openid-client-secret openid-config/openid-client-section)
                           (active-config/access openid-config openid-config/openid-client-scopes openid-config/openid-client-section)
                           (active-config/access openid-config openid-config/openid-client-base-uri openid-config/openid-client-section)
                           (active-config/access openid-config openid-config/openid-client-user-info-from openid-config/openid-client-section)
                           http-client-opts-map)

      (openid-instance-not-available? provider-config-or-error)
      provider-config-or-error)))

(defn- make-openid-profiles!
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

(defn- concat-uris
  [pref post]
  (let [cleaned-pref (if (= \/ (last pref))
                       (apply str (butlast pref))
                       pref)
        cleaned-post (if (= \/ (first post))
                       (apply str (rest post))
                       post)]
    (str cleaned-pref "/" cleaned-post)))

(defn- absolute-redirect-uri
  "Returns the qualified redirect-uri of an `openid-profile`."
  [openid-profile & [uri]]
  (let [base-uri (openid-profile-base-uri openid-profile)]
    (if (empty? uri)
      base-uri
      (concat-uris base-uri uri))))

(defn- join-scopes
  ;; Returns a string containing all configured
  ;; [[openid-profile-scopes]], separated by `\space`.
  [openid-profile]
  (string/join " " (map name (openid-profile-scopes openid-profile))))

(defn- authorize-uri
  [openid-profile state & [redirect-uri]]
  (let [authorize-uri (lens/yank openid-profile (lens/>> openid-profile-openid-provider-config
                                                         openid-provider-config-authorize-endpoint))]
    (str authorize-uri
         (if (string/includes? authorize-uri "?") "&" "?")
         (codec/form-encode {:response_type "code"
                             :client_id     (openid-profile-client-id openid-profile)
                             :redirect_uri  (absolute-redirect-uri openid-profile redirect-uri)
                             :state         state
                             :scope         (join-scopes openid-profile)}))))

(defn- random-state
  []
  (-> (random/base64 9)
      (string/replace "+" "-")
      (string/replace "/" "_")))

(defn logins-from-config!
  [config & [redirect-uri]]
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

(defn- coerce-to-int [n]
  (if (string? n)
    (Integer/parseInt n)
    n))

(defn- parse-params
  [request]
  (if-let [query-string (:query-string request)]
    (codec/form-decode query-string)
    {}))

(defn- get-authorization-code
  [request]
  (get (parse-params request) "code"))

(defn- get-session-state
  [request]
  (get (parse-params request) "state"))

(define-record-type NoAccessToken
  make-no-access-token
  no-access-token?
  [error-message no-access-token-error-message])

(defn- format-access-token
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

(defn- fetch-access-token!
  "For a `openid-profile` and based on a `request` (the response of the
  idp), fetch the actual (JWT) access token.

  Might throw an exception."
  [openid-profile authorization-code redirect-uri grant-type scope]
  (let [access-token-uri (lens/yank openid-profile (lens/>> openid-profile-openid-provider-config
                                                            openid-provider-config-token-endpoint))
        client-id        (openid-profile-client-id openid-profile)
        client-secret    (openid-profile-client-secret openid-profile)
        payload          {:form-params (merge
                                        {:client_id     client-id
                                         :client_secret client-secret
                                         :grant_type grant-type}
                                        (when authorization-code {:code authorization-code})
                                        (when redirect-uri {:redirect_uri (absolute-redirect-uri openid-profile redirect-uri)})
                                        (when scope {:scope scope}))}
        http-client-opts-map (openid-profile-http-client-opts-map openid-profile)]
    (log/log-event! :trace (log/log-msg "Requesting access token from" access-token-uri "with payload" payload (when http-client-opts-map (str "with " http-client-opts-map))))
    (try (let [{:keys [status body]} (http-client/post access-token-uri (merge payload default-http-client-opts http-client-opts-map))]
           (log/log-event! :trace (log/log-msg "Received reply from" access-token-uri ":" status body))
           (case status
             200 (let [access-token-edn (json/read-str body :key-fn csk/->kebab-case-keyword)]
                   (log/log-event! :debug (log/log-msg "Received access-token" access-token-edn))
                   (format-access-token access-token-edn))
             (make-no-access-token (str status " " body))))
         (catch Exception e
           (log/log-exception-event! :error (log/log-msg "Received exception from" access-token-uri ":" (.getMessage e)) e)
           (make-no-access-token (.getMessage e))))))

(defn fetch-access-token-for-authorization!
  [openid-profile authorize-code & [redirect-uri]]
  (fetch-access-token! openid-profile authorize-code redirect-uri "authorization_code" nil))

(defn fetch-access-token-for-graph-api!
  [openid-profile]
  (fetch-access-token! openid-profile nil nil "client_credentials" "https://graph.microsoft.com/.default"))

;; default handler for middleware

(defn default-error-handler
  [request error-string original-uri & [exception]]
  (log/log-event! :trace (log/log-msg "default-error-handler"))
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

(defn- render-available-login
  [available-login]
  [:a {:href (available-login-uri available-login)}
   (available-login-name available-login)])

(defn- render-unavailable-login
  [unavailable-login]
  [:span (unavailable-login-name unavailable-login)
   (str " (" (unavailable-login-error unavailable-login) ")")])

(defn default-login-handler
  [_req availables unavailables]
  (log/log-event! :trace (log/log-msg "default-login-handler"))
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
  (log/log-event! :trace (log/log-msg "default-logout-handler: Redirecting to /"))
  (response/redirect "/"))

(define-record-type ^:private Authenticated
  authenticated
  authenticated?
  [^{:doc "In raw EDN form"} user-info authenticated-user-info])

(define-record-type ^:private AuthenticationStarted
  authentication-started
  authentication-started?
  [state-profile-map authentication-started-state-profile-map
   original-uri authentication-started-original-uri])

(define-record-type ^:private Unauthenticated
  unauthenticated
  unauthenticated?
  [])

(def ^{:private true :doc "The keyword the session lives in the in the request/response map."} state-session :session)
(def ^{:private true :doc "The keyword the authentication-state lives in the session map."} state-auth-state ::auth-state)

(def ^:private state
  (lens/>> state-session state-auth-state))

(defn- authenticated-request?
  [request]
  (authenticated? (state request)))

(defn- authentication-started-request?
  [request]
  (authentication-started? (state request)))

(defn- unauthenticated-request?
  [request]
  (let [st (state request)]
    (or (nil? st)
        (unauthenticated? st)
        (and (authentication-started? st)
             (nil? (get-session-state request))))))

(defn wrap-openid-logout
  "Wrapper that removes authentication information from the current session.
  Use together with [[wrap-openid-authentication]].
  Must be the handler of the route that [[wrap-openid-authentication]] uses
  as its `logout-endpoint`.

  - `:logout-handler`: The handler that this wrapper calls.  It gets called
  with `request`.  Defaults to [[default-logout-handler]] which redirects
  to `/`."
  [& {:keys [logout-handler] :or {logout-handler   default-logout-handler}}]
  (fn [request]
    (log/log-event! :debug (log/log-msg "wrap-openid-logout: removing stored credentials"))
    (-> (logout-handler request)
        (state (unauthenticated)))))

(defn logout-form-hiccup
  "Render a logout form from given `user-info`.  You need to POST to the IDP's
  logout endpoint if the user's id-token is too large to be a parameter in a GET
  request due to too many claims in the token."
  [text user-info]
  (let [user-logout-info (user-info-logout-info user-info)]
    (apply hf/form-to
           [:post (user-logout-info-uri user-logout-info)]
           (hf/submit-button text)
           (mapv (fn [[name value]]
                   (hf/hidden-field name value))
                 (user-logout-info-params-map user-logout-info)))))

(defn logout-href
  "Render a logout link from given `user-info`.  You can use this GET request to
  the IDP's logout endpoint if the user's id-token is small enough to be a
  parameter in a GET request when it does not include too many claims."
  [user-logout-info]
  (str (user-logout-info-uri user-logout-info)
       "?"
       (codec/form-encode (user-logout-info-params-map user-logout-info))))

(defn logout-link-hiccup
  [text user-info]
  [:a {:href (logout-href (user-info-logout-info user-info))} text])

(defn- make-user-logout-info
  [openid-profile id-token-hint logout-endpoint]
  (really-make-user-logout-info
    (let [end-session-endpoint
          (lens/yank openid-profile (lens/>> openid-profile-openid-provider-config
                                             openid-provider-config-end-session-endpoint))]
      end-session-endpoint)
    {"post_logout_redirect_uri" (absolute-redirect-uri openid-profile logout-endpoint)
     "id_token_hint"            id-token-hint}))

(define-record-type NoUserInfo
  make-no-user-info
  no-user-info?
  [error-message no-user-info-error-message])

(defn fetch-user-info!
  "This fetches user info with another request to user-info endpoint.
  See configuration setting [[openid-config/openid-client-user-info-from]]."
  [openid-profile access-token logout-endpoint]
  (let [token (access-token-token access-token)
        token-type (access-token-type access-token)
        id-token (access-token-id-token access-token)]
    (when token
      (let [user-info-uri (lens/yank openid-profile (lens/>> openid-profile-openid-provider-config
                                                             openid-provider-config-userinfo-endpoint))
            http-client-opts-map (lens/yank openid-profile openid-profile-http-client-opts-map)
            payload       {:headers {:authorization (str token-type " " token)}}]
        (log/log-event! :trace (log/log-msg "Requesting user info from" user-info-uri "with payload" payload (when http-client-opts-map (str "with " http-client-opts-map))))
        (try
          (let [{:keys [status body]} (http-client/get user-info-uri (merge payload default-http-client-opts http-client-opts-map))]
            (log/log-event! :trace (log/log-msg "Received response from " user-info-uri ":" status body))
            (case status
              200 (let [user-data-edn (json/read-str body :key-fn csk/->kebab-case-keyword)]
                    (log/log-event! :debug (log/log-msg "Received user info:" user-data-edn))
                    (make-user-info (:preferred-username user-data-edn)
                                    (:name user-data-edn)
                                    (:email user-data-edn)
                                    (:groups user-data-edn)
                                    user-data-edn
                                    openid-profile
                                    (make-user-logout-info openid-profile id-token logout-endpoint)
                                    access-token))
              (make-no-user-info (str status " " body))))
          (catch Exception e
            (log/log-exception-event! :error (log/log-msg "Received exception from" user-info-uri ":" (.getMessage e)) e)
            (make-no-user-info (.getMessage e))))))))

(defn- decode-jwt
  [encoded-jwt]
  (jwt/str->jwt encoded-jwt))

(defn fetch-user-info
  "This decodes user-info from the JWT of the access-token.
  See configuration setting [[openid-config/openid-client-user-info-from]]."
  [openid-profile access-token logout-endpoint]
  (let [encoded-access-token (access-token-token access-token)
        encoded-id-token (access-token-id-token access-token)]
    (try
      (let [access-token-jwt (decode-jwt encoded-access-token)
            id-token-jwt (decode-jwt encoded-id-token)
            access-claims (:claims access-token-jwt)
            id-claims (:claims id-token-jwt)
            claims {:access-claims access-claims
                    :id-claims id-claims}]
        ;; TODO: make this mapping configurable
        (make-user-info (get-in claims [:access-claims :unique_name])
                        (get-in claims [:access-claims :name])
                        (or (get-in claims [:access-claims :email])
                            (get-in claims [:id-claims :email]))
                        (or (get-in claims [:access-claims :groups])
                            (get-in claims [:id-claims :roles]))
                        claims
                        openid-profile
                        (make-user-logout-info openid-profile encoded-id-token logout-endpoint)
                        access-token))
      (catch Exception e
            (log/log-exception-event! :error (log/log-msg "Exception from decoding JWT access-token" (pr-str access-token) ":" (.getMessage e)) e)
            (make-no-user-info (.getMessage e))))))

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
  session.  Defaults to [[default-logout-endpoint]].  This must match the
  route that [[wrap-openid-logout]] uses.

  - `:error-handler`: Handler thet the middleware calls in case of some
  unexpected error.  The error handler gets called with these arguments:
     - `request`: The current request
     - `error-string`: A string that describes the error
     - `original-uri`: The URI of the original request, useful to try request
       again
     - and optionally an `exception`
  Defaults to [[default-error-handler]].

  - `:stubborn-idp-login-endpoint`: Some IDPs (or their admins) might require a
  specific login endpoint URI that is different from the recommended base URI.
  You can set that endpoint here, it gets concatenated onto base URI.
  Defaults to the empty string.
  "
  [config & {:keys [login-handler
                    logout-endpoint
                    error-handler
                    stubborn-idp-login-endpoint]
             :or   {login-handler   default-login-handler
                    logout-endpoint default-logout-endpoint
                    error-handler   default-error-handler
                    stubborn-idp-login-endpoint ""}}]
  (log/log-event! :trace (log/log-msg "wrap-openid-authentication*: setting up auth middleware"))
  (fn [handler]
    (fn [request]
      (log/log-event! :trace (log/log-msg "wrap-ensure-authenticated: request" request))
      (try
        (cond
          (unauthenticated-request? request)
          (do
            (log/log-event! :debug (log/log-msg "wrap-ensure-authenticated: unauthenticated" (pr-str (state request))))
            (let [original-uri (:uri request)
                  logins (logins-from-config! config stubborn-idp-login-endpoint)]
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
                      access-token (fetch-access-token-for-authorization! openid-profile (get-authorization-code request) stubborn-idp-login-endpoint)]
                  (if (no-access-token? access-token)
                    (-> (error-handler request (str "Got no access token - " (no-access-token-error-message access-token)) original-uri)
                        (state (unauthenticated)))
                    (do
                      (log/log-event! :trace (log/log-msg "wrap-ensure-authenticated: got access-token" (pr-str access-token)))
                      (let [user-info-fetcher (case (openid-profile-user-info-from openid-profile)
                                                :jwt fetch-user-info
                                                :endpoint fetch-user-info!)
                            user-info (user-info-fetcher openid-profile access-token logout-endpoint)]
                        (if (no-user-info? user-info)
                          (-> (error-handler request (str "Got no user info - " (no-user-info-error-message user-info)) original-uri)
                              (state (unauthenticated)))

                          (do
                            (log/log-event! :trace (log/log-msg "wrap-ensure-authenticated: got user-info" (pr-str user-info)))
                            (let [user-info-edn (user-info-lens {} user-info)]
                              (log/log-event! :info (log/log-msg "Successfully logged in user" (user-info-id user-info)))
                              (log/log-event! :info (log/log-msg "Redirecting to absolute original-uri" (absolute-redirect-uri openid-profile original-uri)))
                              (-> (response/redirect (absolute-redirect-uri openid-profile original-uri))
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
  [& [session-store]]
  (log/log-event! :trace (log/log-msg "wrap-openid-session: setting up session"
                                      (when session-store (str ", using existing session store" (pr-str session-store)))))
  (let [session-store  (or session-store (ring-session-memory/memory-store))
        session-config (-> (:session ring-defaults/site-defaults)
                           (assoc :store session-store)
                           (assoc :cookie-name "active-openid-session")
                           (assoc-in [:cookie-attrs :same-site] :lax))]
    (fn [handler]
      (-> handler
          (ring-session/wrap-session session-config)))))

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
  (let [the-openid-auth (wrap-openid-authentication* config args)
        the-openid-session (wrap-openid-session session-store)]
    (fn [handler] ;; FIXME: add & args to the parameter-list here, because of reitit
      (-> handler
          the-openid-auth
          the-openid-session))))

(defn maybe-user-info-from-request
  "Retrieve [[UserInfo]] for logged in user from `request`.
  Use this function in your handler to obtain information about your user."
  [request]
  (let [state (state request)
        user-info-edn (and (authenticated? state) (authenticated-user-info state))]
    (if user-info-edn
      (user-info-lens user-info-edn)
      nil)))
