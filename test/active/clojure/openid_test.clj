(ns active.clojure.openid-test
  (:require [active.clojure.openid :as openid]
            [clojure.test :as t]))

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
