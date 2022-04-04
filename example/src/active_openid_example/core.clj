
(ns active-openid-example.core
  (:require [active.clojure.config :as active-config]
            [active.clojure.lens :as lens]
            [active.clojure.logger.event :as log]
            [active.clojure.logger.log4j :as log4j]
            [active.clojure.oidc :as oidc]
            [active.clojure.oidc.config :as oidc-config]
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
  [oidc-profiles access-tokens]
  ;; There is at most one session.
  (let [[oidc-profile token token-type]
        (->> oidc-profiles
             (mapv (fn [oidc-profile]
                     [oidc-profile
                      (get-in access-tokens [(oidc/oidc-profile-name oidc-profile) :token])
                      (get-in access-tokens [(oidc/oidc-profile-name oidc-profile) :extra-data :token_type])]))
             (filter (comp some? second))
             first)]
    (when token
      (let [response
            (http-client/get (lens/yank oidc-profile (lens/>> oidc/oidc-profile-openid-provider-config
                                                              oidc/openid-provider-config-userinfo-endpoint))
                             {:headers {:authorization (str token-type " " token)}})]
        (when (= (:status response) 200)
          (let [user-data (json/read-str (:body response) :key-fn csk/->kebab-case-keyword)]
            {:id     (:id user-data)
             :login  (:username user-data)
             :name   (:name user-data)
             :source (oidc/oidc-profile-name oidc-profile)
             :rest user-data}))))))

(defn app-handler
  [oidc-profiles]
  (fn [req]
    (let [user-info (or (-> req :session :user-info)
                        (fetch-user-data oidc-profiles (-> req :session ::oidc/access-tokens)))
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
                                (mapv (fn [oidc-profile]
                                        (let [check-session-iframe
                                              (-> (oidc/oidc-profile-openid-provider-config oidc-profile)
                                                  oidc/openid-provider-config-check-session-endpoint)]
                                          [:div
                                           [:p
                                            [:a {:href (oidc/oidc-profile-launch-uri oidc-profile)}
                                             (str "Login via " (oidc/oidc-profile-name oidc-profile))]]]))
                                      oidc-profiles))]])}
          session   (-> (:session req)
                        (assoc :user-info user-info))]
      (-> resp
          (assoc :session session)))))

(defn logout-handler
  [oidc-profile]
  (fn [req]
    (let [end-session-endpoint
          (lens/yank oidc-profile (lens/>> oidc/oidc-profile-openid-provider-config
                                           oidc/openid-provider-config-end-session-endpoint))]
      (oidc/oidc-logout oidc-profile))))

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
  (let [oidc-profiles (oidc/make-oidc-profiles! config)]
    (rr/ring-handler 
     (rr/router
      (concat (oidc/reitit-routes oidc-profiles)
              [["/" {:get {:handler (fn [_] (response/redirect "/login"))}}]
               ["/login"  {:get {:handler (app-handler oidc-profiles)}}]
               ["/logout" {:get {:handler (logout-handler (first oidc-profiles))}}]])
      {:data {:middleware [[ring-session/wrap-session (:session ring-config)]
                           [ring-cookies/wrap-cookies]]}}))))

(def server (atom nil))

(defn start-server
    [config]
    (reset! server (jetty/run-jetty (app config) {:host "0.0.0.0"
                                                 :port 1414
                                                 :join? false})))

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
                                                                            oidc-config/section)
                                                      []))]
    (log4j/redirect-log4j!)
    (log/set-global-log-events-config-from-map! {:min-level :info})
    (start-server config)))

(run)
(stop-server)
