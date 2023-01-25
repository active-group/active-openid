(ns active-openid-example.core
  (:require [active.clojure.config :as active-config]
            [active.clojure.logger.event :as log]
            [active.clojure.openid :as openid]
            [active.clojure.openid.config :as openid-config]
            [clojure.edn :as edn]
            [hiccup.page :as hp]
            [reitit.ring :as rr]
            [ring.adapter.jetty :as jetty]
            [ring.middleware.cookies :as ring-cookies]
            [ring.middleware.defaults :as ring-defaults]
            [ring.middleware.params :as ring-params]
            [ring.middleware.session :as ring-session]
            [ring.middleware.session.memory :as ring-session-memory])
  (:gen-class))

(def session-store (ring-session-memory/memory-store))

(def ring-config
  (-> ring-defaults/site-defaults
      (assoc-in [:session :store] session-store)
      (assoc-in [:session :cookie-attrs :same-site] :lax)))

(defn application
  [req]
  (let [user-info (openid/request-user-info req)]
    {:status 200
     :headers {"Content-Type" "text/html"}
     :body
     (hp/html5
      [:head [:meta {:charset "UTF-8"}]]
      [:body
       [:main
        [:div
         [:h1 "Logged in!"]
         [:h2 "session"]
         [:code (pr-str (:session req))]]
        [:div
         [:h2 "user info"]
         [:code (pr-str user-info)]]
        (when user-info
          [:div
           [:h2 "logout"]
           [:a {:href (openid/user-info-logout-uri user-info)} "Logout"]])]])}))

(defn app
  [config]
  (rr/ring-handler
    (rr/router
      [["/" {:get {:handler application}}]
       [["/deep/link/" {:get {:handler application}}]]])
    (rr/create-default-handler)
    {:middleware [[ring-session/wrap-session (:session ring-config)]
                  [ring-cookies/wrap-cookies]
                  [ring-params/wrap-params]
                  [(openid/wrap-openid-authentication* config)]]}))

(defonce server (atom nil))

(def server-config {:host  "localhost"
                    :port  1414
                    :join? false})

(defn start-server!
  [config]
  (reset! server (jetty/run-jetty (app config) server-config)))

(defn stop-server!
    []
    (try
     (.stop @server)
    (catch Exception _
       nil)
    (finally
       (reset! server nil))))

(defn run-server!
  []
  (let [config (->> (slurp "./etc/config.edn")
                    edn/read-string
                    (active-config/make-configuration openid-config/openid-schema []))]
    (log/set-global-log-events-config-from-map! {:min-level :debug
                                                 :ns-filter {:deny #{"*jetty*" "org.apache.*"}}})
    (start-server! config)))

(defn main
  [& _args]
  (stop-server!)
  (run-server!))

;; (-main)
