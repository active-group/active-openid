(ns ^:no-doc active.clojure.openid.intermediate-store
  "Stores some info while waiting for IDP callback."
  (:refer-clojure :exclude [contains?])
  (:import (java.time Instant)))

(defn new! []
  (atom {}))

(defrecord ^:private Data [info timeout-time])

(defn- now! []
  (.getEpochSecond (Instant/now)))

(defn- now-plus! [seconds]
  (+ (now!) seconds))

(defn remember!
  "Store info under id, for at least the given seconds"
  [store id info timeout-seconds]
  (swap! store assoc id (Data. info (now-plus! timeout-seconds)))
  nil)

(defn- cleanup [m]
  ;; remove all that are timed out
  (let [t (now!)]
    (reduce-kv (fn [r id d]
                 (if (< (:timeout-time d) t)
                   r ;; drop id
                   (assoc r id d)))
               {}
               m)))

(defn contains? [store id]
  ;; be carefule not to assume that it is still there when take! is called
  (some? (get @store id)))

(defn take!
  "Returns stored info or nil."
  [store id]
  (when-let [d (get @store id)]
    (if (compare-and-set! store @store (->  @store
                                            (dissoc id)
                                            (cleanup)))
      (:info d)
      (take! store id))))
