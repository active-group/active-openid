(ns active-openid-example.backend-for-frontend
  (:require [active.clojure.config :as active-config]
            [active.clojure.logger.event :as log]
            [active.clojure.openid :as openid]
            [active.clojure.openid.config :as openid-config]
            [clojure.edn :as edn]
            [hiccup.page :as hp]
            [reitit.ring :as rr]
            [ring.adapter.jetty :as jetty]
            [clj-http.client :as http-client]
            [clojure.string :as str])
  (:gen-class))

;; This example implements the "Backend-for-Frontend" architecture pattern
;; See https://datatracker.ietf.org/doc/html/draft-ietf-oauth-browser-based-apps#name-backend-for-frontend-bff

(defn forward-request
  [req]
  (let [{:keys [scheme
                server-name
                server-port
                uri
                query-string
                request-method
                headers
                body]} req

        new-path (-> uri
                     (str/replace-first #"^/api/" "/"))

        target-url (str "http://localhost:1417"
                        new-path
                        (when query-string
                          (str "?" query-string)))]

    {:method request-method
     :url target-url
     :headers (dissoc headers "host")
     :body body
     :as :stream
     :throw-exceptions false}))

(defn api [req]
  (if-let [user-info (openid/maybe-user-info-from-request req)]
    ;; get token from user-info, forward enriched request to real API
    (let [token (openid/access-token-token
                 (openid/user-info-access-token user-info))
          req* (assoc-in (forward-request req)
                         [:headers "authorization"]
                         (str "Bearer " token))]
      (log/log-event! :trace (log/log-msg "Running request for application server" (pr-str req*)))
      (http-client/request req*))
    ;; else not logged in yet
    {:status 401}))

(defn app
  [config]
  (rr/ring-handler

   (rr/router
    [["/api/*" {:get {:handler api}}]])

   (rr/routes
    (rr/create-resource-handler {:path "/"})
    (rr/create-default-handler))
   {:middleware
    [(openid/wrap-openid-session)
     (openid/wrap-automatic-refresh)
     (openid/wrap-openid-authentication*
      config
      :login-handler
      (fn [req availables unavailables]
        (if-let [available (first availables)]
          {:status 302
           :headers {"Location"
                     (openid/available-login-uri available)}}
          {:status 200
           :body "No login services available"})))]}))

(defonce server (atom nil))

(def server-config {:host  "localhost"
                    :port  1414
                    :join? false})

(defn start-server!
  [config]
  (reset! server (jetty/run-jetty (#'app config) server-config)))

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
    (log/set-global-log-events-config-from-map! {:min-level :error #_:trace
                                                 :ns-filter {:deny #{"*jetty*" "org.apache.*"}}})
    (start-server! config)))

(defn main
  [& _args]
  (stop-server!)
  (run-server!))

;; Uncomment to run BFF
#_(main)

;; --- Application (API) server

(def application-server-config
  (let [raw (->> (slurp "./etc/config.edn")
                 edn/read-string)
        first-profile (first (:openid-profiles raw))]
    {:client-id (:id (:client first-profile))
     :client-secret (:secret (:client first-profile))}))

(defn valid-access-token?! [tok]
  (get
   (cheshire.core/decode
    (:body
     (http-client/request
      {:method :post
       ;; TODO: take from well-known config
       :url "http://localhost:8080/realms/active-openid-example-realm/protocol/openid-connect/token/introspect"
       :headers {"Content-type" "application/x-www-form-urlencoded"}
       :body
       (str "token=" tok "&"
            "client_id=" (:client-id application-server-config) "&"
            "client_secret=" (:client-secret application-server-config))})))
   "active"))

(defn request-access-token [req]
  (let [hdr (get-in req [:headers "authorization"])]
    (subs hdr (count "Bearer "))))

(def api-handler
  (rr/ring-handler
   (rr/router
    [["/nuke" {:get {:handler (fn [req]
                                (if (valid-access-token?! (request-access-token req))
                                  {:status 200
                                   :body "successfully started some nukes"}
                                  {:status 401}))}}]])
   (rr/routes
    (rr/create-default-handler))))

(defonce application-server (atom nil))

(defn start-application-server! []
  (reset! application-server (jetty/run-jetty #'api-handler {:host "localhost"
                                                             :port 1417
                                                             :join? false})))

(defn stop-application-server! []
  (try
    (.stop @application-server)
    (catch Exception _
      nil)
    (finally
      (reset! application-server nil))))

(defn restart-application-server! []
  (stop-application-server!)
  (start-application-server!))

;; Uncomment to run mock application server
#_(restart-application-server!)
