(ns active-openid-example.core
  (:require [active.clojure.config :as active-config]
            [active.clojure.lens :as lens]
            [active.clojure.logger.event :as log]
            [active.clojure.openid :as openid]
            [active.clojure.openid.config :as openid-config]
            [active.clojure.record :refer [define-record-type]]
            [camel-snake-kebab.core :as csk]
            [clj-http.client :as http-client]
            [clojure.data.json :as json]
            [clojure.edn :as edn]
            [clojure.string :as string]
            [hiccup.page :as hp]
            [reitit.ring :as rr]
            [ring.adapter.jetty :as jetty]
            [ring.middleware.cookies :as ring-cookies]
            [ring.middleware.defaults :as ring-defaults]
            [ring.middleware.session :as ring-session]
            [ring.middleware.session.cookie :as ring-session-cookie]
            [ring.middleware.session.memory :as ring-session-memory]
            [ring.util.codec :as codec]
            [ring.util.response :as response]))

(def session-store (ring-session-memory/memory-store))

(def ring-config
  (-> ring-defaults/site-defaults
      (assoc-in [:session :store] session-store)
      (assoc-in [:session :cookie-attrs :same-site] :lax)))

(defn fetch-user-data
  [openid-profiles access-tokens]
  ;; There is at most one session.
  (let [[openid-profile token token-type]
        (->> openid-profiles
             (mapv (fn [openid-profile]
                     [openid-profile
                      (get-in access-tokens [(openid/openid-profile-name openid-profile) :token])
                      (get-in access-tokens [(openid/openid-profile-name openid-profile) :extra-data :token_type])]))
             (filter (comp some? second))
             first)]
    (when token
      (let [response
            (http-client/get (lens/yank openid-profile (lens/>> openid/openid-profile-openid-provider-config
                                                              openid/openid-provider-config-userinfo-endpoint))
                             {:headers {:authorization (str token-type " " token)}})]
        (when (= (:status response) 200)
          (let [user-data (json/read-str (:body response) :key-fn csk/->kebab-case-keyword)]
            {:id     (:id user-data)
             :login  (:username user-data)
             :name   (:name user-data)
             :source (openid/openid-profile-name openid-profile)
             :rest user-data}))))))

(defn app-handler
  [openid-profiles]
  (fn [req]
    (let [user-info (or (-> req :session :user-info)
                        (fetch-user-data openid-profiles (-> req :session ::openid/access-tokens)))
          resp      {:status  200
                     :headers {"Content-Type" "text/html"}
                     :body
                     (hp/html5
                      [:head [:meta {:charset "UTF-8"}]]
                      [:body
                       [:main
                        [:div
                         [:h2 "session"]
                         [:code (pr-str (:session req))]]
                        [:div
                         [:h2 "user info"]
                         [:code (pr-str user-info)]]
                        (concat [[:p
                                  [:a {:href "/"} "Home"]]
                                 (when user-info
                                   [:p
                                    [:a {:href "/logout"} "Logout"]])]
                                (mapv (fn [openid-profile]
                                        (let [check-session-iframe
                                              (-> (openid/openid-profile-openid-provider-config openid-profile)
                                                  openid/openid-provider-config-check-session-endpoint)]
                                          [:div
                                           [:p
                                            [:a {:href (openid/launch-uri openid-profile)}
                                             (str "Login via " (openid/openid-profile-name openid-profile))]]]))
                                      openid-profiles))]])}
          session   (-> (:session req)
                        (assoc :user-info user-info))]
      (-> resp
          (assoc :session session)))))

(defn logout-handler
  [host+port openid-profiles]
  (fn [req]
    (let [openid-profile (openid/req->openid-profile req openid-profiles)
          ;; TODO: this is the wrong token, we need the id-token-hint,
          ;; not the access_token
          id-token-hint (openid/req->access-token-for-profile req openid-profile)
          end-session-endpoint
          (lens/yank openid-profile (lens/>> openid/openid-profile-openid-provider-config
                                             openid/openid-provider-config-end-session-endpoint))]
      (openid/openid-logout host+port openid-profile id-token-hint))))

(def not-found-handler
  (constantly
   (response/not-found
    (hp/html5
     [:head
      [:meta {:charset "UTF-8"}]]
     [:body
      [:h1 "Not found, sorry"]]))))

(defn app
  [config]
  (let [openid-profiles (openid/make-openid-profiles! config)]
    (rr/ring-handler
     (rr/router
      (concat (openid/reitit-routes openid-profiles)
              [["/" {:get {:handler (fn [_] (response/redirect "/login"))}}]
               ["/login"  {:get {:handler (app-handler openid-profiles)}}]
               ["/logout" {:get {:handler (logout-handler "http://localhost:1414" openid-profiles)}}]])
      {:data {:middleware [[ring-session/wrap-session (:session ring-config)]
                           [ring-cookies/wrap-cookies]]}}))))

(def server (atom nil))

(def server-config {:host  "localhost"
                    :port  1414
                    :join? false})

(defn sc-port [{:keys [port]}]
  port)

(defn sc-host [{:keys [host]}]
  host)

(defn server-config->host+port [sc]
  (str "http://" (sc-host sc) ":" (sc-port sc)))

(defn start-server
  [config]
  (reset! server (jetty/run-jetty (app config) server-config)))

(defn stop-server
    []
    (try
     (.stop @server)
    (catch Exception _
       nil)
    (finally
       (reset! server nil))))

(defn run
  []
  (let [config (->> (slurp "./etc/config.edn")
                    edn/read-string
                    (active-config/make-configuration (active-config/schema "The schema"
                                                                            openid-config/section)
                                                      []))]
    (log/set-global-log-events-config-from-map! {:min-level :info})
    (start-server config)))

(run)
