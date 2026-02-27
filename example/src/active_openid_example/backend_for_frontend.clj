(ns active-openid-example.backend-for-frontend
  (:require [active.clojure.config :as active-config]
            [active.clojure.logger.event :as log]
            [active.clojure.openid :as openid]
            [active.clojure.openid.config :as openid-config]
            [clojure.edn :as edn]
            [ring.adapter.jetty :as jetty]
            [clj-http.client :as http-client]
            [clojure.string :as str]
            [ring.middleware.resource :as resource]
            [active.clojure.record :refer [define-record-type]])
  (:gen-class))

;; This example implements the "Backend-for-Frontend" architecture pattern
;; See https://datatracker.ietf.org/doc/html/draft-ietf-oauth-browser-based-apps#name-backend-for-frontend-bff

;; A request function denotes a function from Ring Request -> Ring Request

(define-record-type RequestFunction
  mk-request-function
  request-function?
  [to-host request-function-to-host
   to-port request-function-to-port
   to-scheme request-function-to-scheme
   to-client-cert request-function-to-client-cert
   from-path-prefix request-function-from-path-prefix
   to-path-prefix request-function-to-path-prefix])

(defn make-request-function
  ([to-host]
   (make-request-function to-host "" ""))
  ([to-host from-path-prefix to-path-prefix]
   (make-request-function to-host 80 from-path-prefix to-path-prefix))
  ([to-host to-port from-path-prefix to-path-prefix]
   (mk-request-function to-host to-port :http nil from-path-prefix to-path-prefix)))

(defn run-request-function [rf]
  (fn [req]
    (let [{:keys [body
                  character-encoding
                  content-length
                  content-type
                  headers
                  protocol
                  query-string
                  remote-addr
                  request-method
                  scheme
                  server-name
                  server-port
                  ssl-client-cert
                  uri]}
          req]

      {:body body
       :character-encoding character-encoding
       :content-length content-length
       :content-type content-type
       :request-method request-method
       :remote-addr remote-addr
       :headers (dissoc headers "host")
       :protocol protocol
       :query-string query-string
       :scheme (request-function-to-scheme rf)
       :server-name (request-function-to-host rf)
       :server-port (request-function-to-port rf)
       :ssl-client-cert (request-function-to-client-cert rf)
       :uri (str/replace-first
             uri
             (re-pattern (str "^" (request-function-from-path-prefix rf)))
             (request-function-to-path-prefix rf))})))

(def to-host-setting
  (active-config/setting :to-host "To host" active-config/string-range))

(def to-port-setting
  (active-config/setting :to-port "To port" (active-config/integer-between-range 0 65534 3128)))

(def from-path-prefix-setting
  (active-config/setting :from-path-prefix "From path prefix" active-config/string-range))

(def to-path-prefix-setting
  (active-config/setting :to-path-prefix "To path prefix" active-config/string-range))

(def request-function-schema
  (active-config/schema
   "Configuration schema for a request function."
   to-host-setting
   to-port-setting
   from-path-prefix-setting
   to-path-prefix-setting))

(defn config->request-function [cfg]
  (make-request-function
   (active-config/access cfg to-host-setting)
   (active-config/access cfg to-port-setting)
   (active-config/access cfg from-path-prefix-setting)
   (active-config/access cfg to-path-prefix-setting)))

(def request-function-section
  (active-config/section :request-function request-function-schema))

(def openid-section
  (active-config/section :openid openid-config/openid-schema))

(def configuration-schema
  (active-config/schema
   "Configuration schema for backend-for-frontend example"
   openid-section
   request-function-section))

(defn make-api [request-function]
  (let [translate-request (run-request-function request-function)]
    (fn [req]
      (if-let [user-info (openid/maybe-user-info-from-request req)]
        ;; get token from user-info, forward enriched request to real API
        (let [token (openid/access-token-token
                     (openid/user-info-access-token user-info))
              req* (-> (translate-request req)
                       (assoc-in [:headers "authorization"] (str "Bearer " token))
                       (assoc-in [:headers "cookie"] nil))]
          (log/log-event! :trace (log/log-msg "Running request for application server" (pr-str req*)))
          ;; TODO: 40x raise exceptions but we just want to passe them on
          (http-client/request req*))
        ;; else not logged in yet
        {:status 401}))))

(defn make-handler [config]
  (let [api (make-api (config->request-function config))]
    (fn [req]
      (if (= "/" (:uri req))
        {:status 200
         :headers {"Content-type" "text/html"}
         :body (slurp "resources/public/index.html")}
        (api req)))))

(defn app
  [config]
  (-> (make-handler (active-config/section-subconfig config request-function-section))
      (resource/wrap-resource "public")
      ((openid/wrap-openid-authentication*
        (active-config/section-subconfig config openid-section)
        :login-handler
        (fn [req availables unavailables]
          (if-let [available (first availables)]
            {:status 302
             :headers {"Location"
                       (openid/available-login-uri available)}}
            {:status 200
             :body "No login services available"}))))
      ((openid/wrap-automatic-refresh))
      ((openid/wrap-openid-session))))

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

(def config
  (->> (slurp "./etc/backend_for_frontend_config.edn")
       edn/read-string
       (active-config/make-configuration configuration-schema [])))

(defn run-server!
  []
  (log/set-global-log-events-config-from-map! {:min-level #_:error :trace
                                               :ns-filter {:deny #{"*jetty*" "org.apache.*"}}})
  (start-server! config))



(defn main
  [& _args]
  (stop-server!)
  (run-server!))

;; Uncomment to run BFF
#_(main)

;; --- Application (API) server

(def application-server-config
  (let [openid-config (active-config/access config openid-section)
        first-profile (first (:openid-profiles openid-config))]
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
  (fn [req]
    (if (= (:uri req)
           "/nuke")
      (if (valid-access-token?! (request-access-token req))
        {:status 200
         :body "successfully started some nukes"}
        {:status 401})
      {:status 404})))

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
