(ns active.clojure.openid-test
  (:require [active.clojure.openid :as openid]
            [active.clojure.openid.config :as openid-config]
            [active.clojure.config :as active-config]
            [clojure.test :as t]
            [clojure.string :as string]
            [lambdaisland.uri :as uri]))

(t/deftest maybe-user-info-from-request
  (let [req (fn [auth-state-edn]
              {:session {:active.clojure.openid/auth-state auth-state-edn}})]
    (t/testing "unauthenticated state"
      (t/is (nil? (openid/maybe-user-info-from-request (req nil))))
      (t/is (nil? (openid/maybe-user-info-from-request (req [:active.clojure.openid/unauthenticated])))))

    (t/testing "authenticated state"
      (t/is (= "Charly"
               (openid/user-info-name (openid/maybe-user-info-from-request (req [:active.clojure.openid/authenticated
                                                                                 {:user-info {:name "Charly"}}]))))))

    (t/testing "auth started state"
      (t/is (nil? (openid/maybe-user-info-from-request (req [:active.clojure.openid/authentication-started
                                                             ;; Not sure what a profile-map looks like
                                                             {:state-profile-map {:foo :bar}
                                                              :original-uri "http://invalid.invalid/"}])))))))

(t/deftest absolute-redirect-uri-1-test
  (t/is (= "http://host/foo" (openid/absolute-redirect-uri-1 "http://host/" "/foo")))
  (t/is (= "http://host/foo" (openid/absolute-redirect-uri-1 "http://host" "/foo")))

  (t/is (= "http://host/foo/bar" (openid/absolute-redirect-uri-1 "http://host/foo" "/foo/bar")))
  (t/is (= "http://host/foo/bar" (openid/absolute-redirect-uri-1 "http://host/foo/" "/foo/bar"))))

(defn with-mocked-provider [provider config f]
  (with-redefs [openid/get-openid-provider-config! (fn [provider-name provider-config-uri http-client-opts]
                                                     (assert (= provider-name (:name provider)))
                                                     (assert (= provider-config-uri (:config-uri provider)))
                                                     config)]
    (f)))

(t/deftest authenticate-success-test
  (let [test-provider {:name       "Test"
                       :config-uri "https://invalid.invalid/.well-known/openid-configuration"}
        client-id "client-id"
        base-uri "http://localhost/base"
        callback-uri "http://localhost/base/callback"
        logout-uri "http://invalid.invalid/logout"
        config (active-config/make-configuration openid-config/openid-schema []
                                                 {:openid-profiles [{:provider test-provider
                                                                     :client   {:id     client-id
                                                                                :secret "client-secret"
                                                                                :scopes ["openid"]
                                                                                :base-uri base-uri
                                                                                :user-info-from :jwt}}]})
        
        provider-settings (openid/make-openid-provider-config "http://invalid.invalid/auth"
                                                              "http://invalid.invalid/token"
                                                              "http://invalid.invalid/user"
                                                              logout-uri
                                                              "http://invalid.invalid/check"
                                                              true)
        wrap (openid/wrap-openid-authentication* config
                                                 {:stubborn-idp-login-endpoint callback-uri
                                                  :login-handler (fn [req availables unavailables]
                                                                   ;; this'll usually return a 302 redirection to the authorize-endpoint with certain parameters
                                                                   (assert (= 1 (count availables)))
                                                                   (let [available (first availables)]
                                                                     (assert (= (:name test-provider) (openid/available-login-name available)))
                                                                     (let [login-url (openid/available-login-uri (first availables))]
                                                                       (assert (string/starts-with? login-url (openid/openid-provider-config-authorize-endpoint provider-settings))
                                                                               login-url)
                                                                       (assert {:response_type "code", :client_id client-id, :redirect_uri base-uri, :scope "openid"}
                                                                               (dissoc (uri/query-map login-url) :state))))
                                                                   {:body "login"})}
                                                 )
        handler (wrap (fn [req] {:body "response"}))]
    (with-mocked-provider
      test-provider
      provider-settings
      (fn []
        ;; login if not not authenticated
        (t/is (= "login" (:body (handler {:uri "/test" :body "request"})))
              "Uses the response of the login-handler no authentication info")

        (t/is (= "login" (:body (handler {:uri "/test" :body "request"
                                          :session {:active.clojure.openid/auth-state [:active.clojure.openid/unauthenticated]}})))
              "Uses the response of the login-handler when not authenticated")

        ;; pass request on if authenticated
        (t/is (= "response" (:body (handler {:uri "/test" :body "request"
                                             :session {:active.clojure.openid/auth-state [:active.clojure.openid/authenticated
                                                                                          {:user-info {:name "Charly"}}]}})))
              "Does normal handling when authenticated")

        ;; handle provider callback
        (let [idp-state "fMBljfUqh-1b"
              auth-started (fn []
                             [:active.clojure.openid/authentication-started {:state-profile-map {idp-state {:name "Test", :provider-config {:authorization-endpoint "http://invalid.invalid/auth", :token-endpoint "http://invalid.invalid/token", :userinfo-endpoint "http://invalid.invalid/user", :end-session-endpoint "http://invalid.invalid/logout", :check-session-endpoint "http://invalid.invalid/check", :supports-backchannel-logout? true}, :client-id "client-id", :client-secret "client-secret", :scopes ["openid"], :base-uri "http://localhost/base", :user-info-from :jwt, :http-client-opts-map {:proxy-host nil, :proxy-port nil, :proxy-user nil, :proxy-pass nil, :proxy-ignore-hosts nil}}}, :original-uri "/test"}]
                             )
              code "89023492834"]

          (let [test-token (openid/make-access-token "17f" :type "refresh-17f" "id-1839" "expire datetime" "refresh-expire datetime" {})
                user-info (fn [openid-profile access-token logout-endpoint]
                            (openid/make-user-info "userid" "user name" "user email" ["group1"] ["claim x"]
                                                   openid-profile
                                                   (openid/really-make-user-logout-info logout-endpoint {:param "x"})
                                                   access-token))]

            (with-redefs
              [openid/fetch-access-token-for-authorization! (fn [openid-profile acode callback-endpoint]
                                                              (assert (= code acode) acode)
                                                              (assert (= callback-uri callback-endpoint) callback-endpoint)
                                                              test-token)
               openid/fetch-user-info! user-info]
              ;; Note: it currently depends on the session state if callbacks are recognized as such (that should be changed)
              (let [response (handler {:uri callback-uri
                                       :query-string (str "state=" idp-state "&" "code=" code)
                                       :session {:active.clojure.openid/auth-state (auth-started)}})]
                (t/is (= {:status 302
                          :headers {"Location" "http://localhost/test"}}
                         (dissoc response :session :body)))
                (t/is (= :active.clojure.openid/authenticated (first (:active.clojure.openid/auth-state (:session response)))))
                ))))
        ))))
