(ns active-openid-example.core
  (:require [active.clojure.config :as active-config]
            [active.clojure.logger.event :as log]
            [active.clojure.openid :as openid]
            [active.clojure.openid.config :as openid-config]
            [clojure.edn :as edn]
            [hiccup.page :as hp]
            [reitit.ring :as rr]
            [ring.adapter.jetty :as jetty])
  (:gen-class))

(defn application
  [req]
  (let [user-info (openid/user-info-from-request req)]
    {:status 200
     :headers {"Content-Type" "text/html"}
     :body
     (hp/html5
      [:head [:meta {:charset "UTF-8"}]]
      [:body
       [:main
        [:div
         (if user-info
           [:div
            [:h1 "Hello " (or (openid/user-info-name user-info) (openid/user-info-id user-info)) "!"]
            [:p "You are logged in."]
            [:h2 "logout"]
            [:h3 "logout with GET"]
            (openid/logout-link-hiccup "Logout" user-info)
            [:h3 "logout with POST"]
            (openid/logout-form-hiccup "Logout" user-info)
            [:h3 "user info debugging:"]
            [:code (pr-str user-info)]]
           [:div
            ;; Note that this should never be shown since the middleware
            ;; supersecedes unauthenticated state with the login page.
            [:h1 "You are not logged in."]])
         [:h3 "session debugging:"]
         [:code (pr-str (:session req))]]]])}))

(defn app
  [config]
  (rr/ring-handler
    (rr/router
      [["/" {:get {:handler application}}]
       ["/deep/link/" {:get {:handler application}}]
       ;; FIXME: "/logout" invariant
       ["/logout" (openid/wrap-openid-logout)]]
      {:data {:middleware [(openid/wrap-openid-authentication config :logout-endpoint "/logout")]}})
    (rr/create-default-handler)))

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
    (log/set-global-log-events-config-from-map! {:min-level :trace #_:debug
                                                 :ns-filter {:deny #{"*jetty*" "org.apache.*"}}})
    (start-server! config)))

(defn main
  [& _args]
  (stop-server!)
  (run-server!))

;; (-main)
