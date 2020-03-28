package web

import (
	"log"
	"net/http"

	"github.com/gorilla/mux"
)

// Vars
var Version, Siem, SiemAddr, SiemPortApi, SiemUrlApi, SiemToken, RulePath, RuleBakPath string
var SiemPortInput uint


func headerMiddleware(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "SigmaShooter")
		w.Header().Set("X-Powered-By", "ppll0p1s")
		w.Header().Set("X-Message", "hunt hunt hunt")
		w.Header().Set("X-Clacks-Overhead", "GNU Terry Pratchett")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "sameorigin") // deny
		w.Header().Set("X-XSS-Protection", "1; mode=block")

		h.ServeHTTP(w, r)
	})
}

// Router: Routes all the requests to the correct handler
func Router(addr, port string) {

	// New route multiplexer
	r := mux.NewRouter()

	// Main routes
	r.HandleFunc("/", indexHandler).Methods("GET")
	r.HandleFunc("/getFolderList", getFolderList).Methods("GET")
	r.HandleFunc("/getLastAlertsCountByDay", getLastAlertsCountByDay).Methods("GET")
	r.HandleFunc("/getJsonRulesTree", getJsonRulesTree).Methods("GET")
	r.HandleFunc("/uploadEditRule", uploadEditRule).Methods("POST")
	r.HandleFunc("/getLastExecutionsLogs", getLastExecutionsLogs).Methods("GET")
	r.HandleFunc("/executionsLog.csv", downloadExecLogs).Methods("GET")
	r.HandleFunc("/infoEditRule", infoEditRule).Methods("POST")
	r.HandleFunc("/editRule", editRule).Methods("POST")
	r.HandleFunc("/newNodeName", newNodeName).Methods("POST")
	r.HandleFunc("/movednd", moveDnd).Methods("POST")
	r.HandleFunc("/addFolder", addFolder).Methods("POST")
	r.HandleFunc("/addRule", getPathToAddRule).Methods("POST")
	r.HandleFunc("/getRootRulePath", getRootRulePath).Methods("GET")

	// API Routes
	r.HandleFunc("/api/checkConn", checkConn).Methods("GET")
	r.HandleFunc("/api/upload", uploadHandler).Methods("POST")
	r.HandleFunc("/api/uploadSingleRule", uploadSingleRuleHandler).Methods("POST")
	r.HandleFunc("/api/download", downloadHandler).Methods("GET")
	r.HandleFunc("/api/deleteRule", deleteRuleHandler).Methods("POST")
	r.HandleFunc("/api/delete", deleteHandler).Methods("GET")
	r.HandleFunc("/api/runRule/{days:[0-9]+}", runRule).Methods("POST")
	r.HandleFunc("/api/runAllRules/{days:[0-9]+}", runAllRules).Methods("GET")
	r.HandleFunc("/api/rules/count", rulesCountHandler).Methods("GET")
	r.HandleFunc("/api/testRules", testRulesHandler).Methods("GET")
	r.HandleFunc("/api/testRuleFile", testRuleFileHandler).Methods("POST")
	r.HandleFunc("/api/testRuleManual", testRuleManualHandler).Methods("POST")

	// Uploading Logs to SIEM
	r.HandleFunc("/logstosiem", logstosiemHandler).Methods("GET")
	r.HandleFunc("/api/uploadWinToSiemAndRun", uploadWinToSiemAndRun).Methods("POST")
	r.HandleFunc("/getLastFilesUploadedLogs", getLastFilesUploadedLogs).Methods("GET")
	r.HandleFunc("/logFileUploaded.csv", downloadFileUploadedLogs).Methods("GET")


	// Serve static files
	r.PathPrefix("/").Handler(http.FileServer(http.Dir("./static/")))

	// Sets r to middleware
	http.Handle("/", headerMiddleware(r))

	// Starts serving, 
	log.Printf("Listening on: https://%s:%s", addr, port)
	/*
	Simple Golang HTTPS/TLS Examples:
	https://gist.github.com/denji/12b3a568f092ab951456
	*/
	err := http.ListenAndServeTLS(addr+":"+port, "server.crt", "server.key", nil)
	if err != nil {
        log.Fatal("ListenAndServeTLS: ", err)
    }
}
