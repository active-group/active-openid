(ns build
  (:require [clojure.tools.build.api    :as b]
            [clojure.tools.deps.cli.api :as cli]
            [deps-deploy.deps-deploy    :as dd]))


(def -version [0 2 5])

(let [[major minor patch] -version]
  (def release-version (format "%s.%s.%s" major minor patch))
  (def snapshot-version (format "%s.%s.%s-SNAPSHOT" major (inc minor) 0)))

(def lib 'de.active-group/active-openid)
(def class-dir "target/classes")
(def basis (b/create-basis {:project "deps.edn"}))

(defn jar-file
  [version]
  (format "target/%s-%s.jar" (name lib) version))

(defn clean [_]
  (b/delete {:path "target"}))

(def git-scm-url (b/git-process {:git-args "config --get remote.origin.url"}))

(defn- parse-github-url
  "Parses a GitHub URL returning a [username repo] pair."
  [url]
  (if url
    (next
     (or (re-matches #"(?:[A-Za-z-]{2,}@)?github.com:([^/]+)/([^/]+).git" url)
         (re-matches #"[^:]+://(?:[A-Za-z-]{2,}@)?github.com/([^/]+)/([^/]+?)(?:.git)?" url)))))

(defn- github-url [url]
  (if-let [[user repo] (parse-github-url url)]
    (str "https://github.com/" user "/" repo)))

(defn build-jar!
  [version]
  (let [jar-file (jar-file version)]
    (b/write-pom {:class-dir class-dir
                  :lib       lib
                  :version   version
                  :basis     basis
                  :src-dirs  ["src"]
                  :scm       {:url (github-url git-scm-url)}
                  :pom-data  [[:licenses
                               [:license
                                [:name "Eclipse Public License 1.0"]
                                [:url "https://opensource.org/license/epl-1-0/"]
                                 [:distribution "repo"]]]]})
    (b/copy-dir {:src-dirs   ["src" "resources"]
                 :target-dir class-dir})
    (b/jar {:class-dir class-dir
            :jar-file  jar-file})
    jar-file))

(defn jar [_]
  (build-jar! release-version))

(defn deploy!
  [version]
  (dd/deploy {:installer :remote
              :artifact  (build-jar! version)
              :pom-file  (b/pom-path {:lib       lib
                                      :class-dir class-dir})}))

(defn deploy [_]
  (deploy! release-version))

(defn deploy-snapshot [_]
  (deploy! snapshot-version))

(defn install-snapshot [_]
  (cli/mvn-install {:jar (build-jar! snapshot-version)}))
