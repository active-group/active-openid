(ns active.clojure.oidc-test
  (:require [active.clojure.oidc :as oidc]
            [clojure.test :as t]
            [active.clojure.config :as active-config]
            [active.clojure.oidc.config :as oidc-config]
            [clojure.string :as string]
            [ring.util.codec :as codec]))

(def config-map
  {:openid-connect
   [{:name          "keycloak"
     :host          "localhost"
     :port          8080
     :scheme        "http"
     :realm         "active-group"
     :client        "oidc-test"
     :client-secret "<redacted>"
     :scopes        ["username" "email"]
     :launch-uri    "/auth/login"
     :redirect-uri  "/auth/login-callback"
     :logout-uri    "/auth/logout"
     :basic-auth?   true}]})

(def config (active-config/make-configuration (active-config/schema "Test configuration schema"
                                                                    oidc-config/section)
                                              []
                                              config-map))

(t/deftest make-authorize-url-test
  (t/testing "with explicit port"
    (t/is (= "http://localhost:8080/auth/realms/test-realm/protocol/openid-connect/auth"
             (oidc/make-authorize-uri "http" "localhost" 8080 "test-realm"))))
  (t/testing "without a port"
    (t/is (= "http://localhost/auth/realms/test-realm/protocol/openid-connect/auth"
             (oidc/make-authorize-uri "http" "localhost" nil "test-realm")))))

(t/deftest make-token-url-test
  (t/testing "with explicit port"
    (t/is (= "http://localhost:8080/auth/realms/test-realm/protocol/openid-connect/token"
             (oidc/make-token-uri "http" "localhost" 8080 "test-realm"))))
  (t/testing "without a port"
    (t/is (= "http://localhost/auth/realms/test-realm/protocol/openid-connect/token"
             (oidc/make-token-uri "http" "localhost" nil "test-realm")))))

(t/deftest make-oidc-profiles-test
  (t/is (= [(oidc/make-oidc-profile
             "keycloak"
             "http://localhost:8080/auth/realms/active-group/protocol/openid-connect/auth"
             "http://localhost:8080/auth/realms/active-group/protocol/openid-connect/token"
             "http://localhost:8080/auth/realms/active-group/protocol/openid-connect/userinfo"
             "oidc-test"
             "<redacted>"
             ["username" "email"]
             "/auth/login"
             "/auth/login-callback"
             "/"
             "/auth/logout"
             true)]
           (oidc/make-oidc-profiles config))))

(def keycloak-oidc
  (first (oidc/make-oidc-profiles config)))

(t/deftest join-scopes-test
  (t/is (= "username email" (oidc/join-scopes keycloak-oidc))))

(t/deftest make-launch-handler-test
  (let [resp ((oidc/make-launch-handler keycloak-oidc) {:requets-method :get
                                                        :uri            "/auth/login"})
        loc  (get-in resp [:headers "Location"])]
    (t/is (= 302 (:status resp)))
    (t/is (string/includes? loc "http://localhost:8080/auth/realms/active-group/protocol/openid-connect/auth?"))
    (t/is (string/includes? loc "response_type=code"))
    (t/is (string/includes? loc "client_id=oidc-test"))))
