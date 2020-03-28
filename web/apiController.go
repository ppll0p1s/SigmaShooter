package web

import (
	//"fmt"
	//"reflect"

	"net/http"
	"regexp"
	"os/exec"
	"time"
	"log"
	"io"
	"strconv"
	"os"
	"io/ioutil"
	"encoding/json"
	"strings"
	"encoding/csv"

	"github.com/gorilla/mux"
)


// checkConn: delete sigma rules from tree
func checkConn(w http.ResponseWriter, r *http.Request){
	log.Println("Executed: checkConn")
	
	var err error

	if Siem == "graylog" {
		err = checkConnGraylog()
	} else if Siem == "X" {
		log.Println("In construction...")
		os.Exit(3)
	} else {
		log.Println("In construction...")
		os.Exit(3)
	}

	if err == nil {
		data := struct {
			Err   int 	 `json:"err"`
			Conn  string `json:"conn"`
		}{
			0,
			"OK",
		}

		ajaxResponse(w, data)
		return
	} else {
		data := struct {
			Err   int 	 `json:"err"`
			Conn  string `json:"conn"`
		}{
			0,
			"NO OK",
		}

		ajaxResponse(w, data)
		return
	}

}

// uploadHandler: upload Sigma rules
func uploadHandler(rw http.ResponseWriter, req *http.Request) {
	log.Println("Executed: uploadHandler")

	file, handler, err := req.FormFile("rulesFile")
	if err != nil {
		http.Error(rw, "Please, send me a valid file", http.StatusInternalServerError)
		return
	}
	defer file.Close()

	// Check file extension
	fnameRegex := regexp.MustCompile(`.tar.gz$`)
	if !fnameRegex.Match([]byte(handler.Filename)) {
		http.Error(rw, "File must be a tar.gz file", http.StatusInternalServerError)
		return
	}

	// Create Backup of last rules before update them
	t := time.Now()
	dateBAK := t.Format("2006-01-02-15:04")
	targzName := "sigmaRules_"+dateBAK
	err = targzit(RulePath,RuleBakPath,targzName)
	if err != nil {
		log.Println("uploadHandler: "+err.Error())
	}

    //fmt.Fprintf(rw, "%v", handler.Header)
	f, err := os.OpenFile(handler.Filename, os.O_WRONLY|os.O_CREATE, 0666)
	if err != nil {
		log.Println("uploadHandler: "+err.Error())
		return
	}
	defer f.Close()
	io.Copy(f, file)

	// Untar tarball rules file into rule path
	if checkNameTarFile(handler.Filename) {
		err = untargzit(handler.Filename,RulePath)
		if err != nil {
			log.Println("uploadHandler: "+err.Error())
		}

		//os.Remove(handler.Filename)
		// Move upload file to tmp
		err = os.Rename(handler.Filename, "tmp/"+handler.Filename)
		if err != nil {
			log.Println("uploadHandler: "+err.Error())
		}
	} else {
		log.Println("uploadHandler: Invalid value, possible attack. Value entered: "+handler.Filename)

		http.Error(rw, "Invalid name.", http.StatusInternalServerError)
		return
	}

	// Wait 5 seconds for alert_submitUpload shown in frontend
	// time.Sleep(5*time.Second)

	http.Redirect(rw, req, "/", http.StatusFound)
	return
}

// uploadSingleRuleHandler: upload single Sigma rule
func uploadSingleRuleHandler(rw http.ResponseWriter, req *http.Request) {
	log.Println("Executed: uploadSingleRuleHandler")

	rulePath := req.FormValue("uploadRulePath")
	file, handler, err := req.FormFile("ruleFile")
	if err != nil {
		http.Error(rw, "Please, send me a valid file", http.StatusInternalServerError)
		return
	}
	defer file.Close()

	// Check file extension
	fnameRegex := regexp.MustCompile(`.yml$`)
	if !fnameRegex.Match([]byte(handler.Filename)) {
		http.Error(rw, "File must be a .yml file", http.StatusInternalServerError)
		return
	}

	// Check if file have already exists
	files, err := FilePathWalkDir(RulePath)
	for _, file := range files {
		fileSplit := strings.Split(file,"/")
		ymlFile := fileSplit[len(fileSplit)-1]
		if handler.Filename == ymlFile {
			http.Error(rw, "There is already a rule with the same name. Please, enter a valid name.", http.StatusInternalServerError)
			return
		}
	}

	f, err := os.OpenFile(handler.Filename, os.O_WRONLY|os.O_CREATE, 0666)
	if err != nil {
		log.Println("uploadSingleRuleHandler: "+err.Error())
		return
	}
	defer f.Close()
	io.Copy(f, file)

	if checkNamePathRule(handler.Filename) && checkNamePath(rulePath) {
		err = os.Rename(handler.Filename, rulePath+handler.Filename)
		if err != nil {
			log.Println("uploadSingleRuleHandler: "+err.Error())
		}
	} else {
		log.Println("uploadSingleRuleHandler: Invalid value, possible attack. Value entered: "+handler.Filename+"\n and: "+rulePath)
	}

	http.Redirect(rw, req, "/", http.StatusFound)
	return
}

// downloadHandler: return a tar.gz file with all active rules
func downloadHandler(w http.ResponseWriter, r *http.Request){
	log.Println("Executed: downloadHandler")

	// Create tar.gz with all active rules
	// Not needed to sanitize
	cmd := exec.Command("tar", "-czf", "sigmaRules.tar.gz", RulePath)
	err := cmd.Run()
	if err != nil {
		log.Println("downloadHandler: "+err.Error())
		return
	}

	// return tar.gz
	w.Header().Set("Content-Type", "application/x-gzip")
	w.Header().Set("Content-Disposition", "attachment; filename=sigmaRules.tar.gz")
	http.ServeFile(w, r, "sigmaRules.tar.gz")
	
}


// runRule: run sigma rule to the SIEM
func runRule(w http.ResponseWriter, r *http.Request){
	log.Println("Executed: runRule")

	if r.Body == nil {
		http.Error(w, "Please send a request body", 400)
		return
	}

	type ajax struct {
		RuleId 	string `json:"ruleId"`
	}
	var reqAjax ajax
	err := json.NewDecoder(r.Body).Decode(&reqAjax)
	if err != nil {
		http.Error(w, err.Error(), 400)
		return
	}

	// Take value from days to execute the query
	vars := mux.Vars(r)
	days, err := strconv.Atoi(vars["days"])
	if err != nil {
		sendJSONError(w, http.StatusInternalServerError, err)
		return
	}


	// get sigma rules
	_, rulePath := getPathRuleNameById(reqAjax.RuleId)
	files, err := FilePathWalkDir(rulePath)
	if err != nil {
		log.Println("runRule: "+err.Error())
	}

	// Var messages to show in frontend
	type FrontendMsg struct {
		Unsupported	int 		`json:"unsupported"`
		Matches 	int 		`json:"matches"`
	}
	frontendMsg := FrontendMsg{0, 0}

	// Check rules number
	if len(files) == 0 {
		http.Error(w, "There are not rules to run. Please make sure you have uploaded some Sigma rule.", http.StatusInternalServerError)
	} else {


    	// Sets alert counter and alerts data variables. Then will be used to log in executionsLog.csv file
		var count int
		var newInfoAlerts [][]string
		var infoAlerts [][]string

    	// Check if executionsLog.csv exists, if not creat it
		if _, err := os.Stat("executionsLog.csv"); os.IsNotExist(err) {
			alertsCsv, err := os.Create("executionsLog.csv")
			if err != nil {
				log.Println("runRule: "+err.Error())
			}

			columns := []string{"Date","SigmaRule","Matches","Alert","logFileUploaded"}
			newInfoAlerts = append(newInfoAlerts, columns)

			csvWriter := csv.NewWriter(alertsCsv)
			csvWriter.WriteAll(newInfoAlerts)
			csvWriter.Flush()
			defer alertsCsv.Close()

		}

		// Start the action, read each rule file
		for _, ruleFile := range files {
			count = 0

			// Get sigma rule content info
			config, err:= getSigmaRuleInfo(ruleFile)
			if err != nil {
				log.Println("runRule: "+err.Error())
			}


			// Run sigmac program to obtein siem query
			out, _ := exec.Command("sigmac", "-t", Siem, ruleFile).Output()
			//fmt.Printf("%s", out)
			query := string(out)

			// NOTE: There are rules that are not supported, skip them and log it. The query from rules unsupported are "" , but the sigmac output is "An unsupported feature is required for this Sigma rule: Aggregations not implemented for this backend Feel free to contribute for fun and fame, this is open source :) -> https://github.com/Neo23x0/sigma" 

			if query == "" {

				log.Println("runRule: Unsupported rule:  " + ruleFile)
		
				t := time.Now()
				tFormat := t.Format("2006-01-02-15:04")
				data := []string{tFormat,ruleFile,"Unsupported",config["title"],""}
				infoAlerts = append(infoAlerts, data)

				frontendMsg.Unsupported = frontendMsg.Unsupported + 1
				
			// And if the rule is OK
			} else {

				if Siem == "graylog" {
					// Adjust query
					newQuery := strings.TrimSuffix(query, "\n") + " AND NOT agentName:SigmaShooterAgent"

					byteValue, err:= runRuleQueryToGraylog(days, newQuery)
					if err != nil {
						log.Println("runRule: "+err.Error())
					}

					// Get result into result interface
					var result map[string]interface{}
					json.Unmarshal([]byte(byteValue), &result)

					// Get number of matches returned from query sigma rule
					numEvents := int(result["total_results"].(float64))
					// If there are not matches
					if numEvents == 0 {

						t := time.Now()
						tFormat := t.Format("2006-01-02-15:04")
						data := []string{tFormat,ruleFile,"0",config["title"],""}
						infoAlerts = append(infoAlerts, data)

					// If there are matches generate an alert and send to graylog
					} else {
						// Get alerts
						messages := result["messages"].([]interface{})
						//fmt.Println(len(messages))

						// And send matches to graylog
						for i:=len(messages)-1; i >= 0; i-- {
							count = count+1

							message := messages[i].(map[string]interface{})
	  						//fmt.Println(message["message"])
							message = message["message"].(map[string]interface{})

							err = sendAlertsToGraylog(ruleFile, config, message)
							if err != nil {
								log.Println("runRule: "+err.Error())
							}
						}

						// Log results 
						t := time.Now()
						tFormat := t.Format("2006-01-02-15:04")

						data := []string{tFormat,ruleFile,strconv.Itoa(count),config["title"],""}
						infoAlerts = append(infoAlerts, data)

						frontendMsg.Matches = frontendMsg.Matches + count
					}

				} else if Siem == "X" {
					log.Println("In construction...")
					os.Exit(3)
				} else {
					log.Println("In construction...")
					os.Exit(3)
				}

			}
			
		}

		// Log results in executionsLog.csv
		alertsCsv, _ := os.OpenFile("executionsLog.csv", os.O_WRONLY|os.O_APPEND, 0644)
		csvWriter := csv.NewWriter(alertsCsv)
		csvWriter.WriteAll(infoAlerts)
		csvWriter.Flush()
		defer alertsCsv.Close()

	}

	var fMsg []FrontendMsg
	fMsg = append(fMsg,frontendMsg)
	data := struct {
		Err   			int          	`json:"err"`
		Msg 			[]FrontendMsg	`json:"runrule_msg"`
	}{
		0,
		fMsg,
	}

	ajaxResponse(w, data)
	return

}

// runAllRules: run all sigma rules to the SIEM
func runAllRules(w http.ResponseWriter, r *http.Request){
	log.Println("Executed: runAllRules")

	// Take value from days to execute the query
	vars := mux.Vars(r)
	days, err := strconv.Atoi(vars["days"])
	if err != nil {
		sendJSONError(w, http.StatusInternalServerError, err)
		return
	}

	// get sigma rules
	files, err := FilePathWalkDir(RulePath)
	if err != nil {
		log.Println("runAllRules: "+err.Error())
	}

	// Var messages to show in frontend
	type FrontendMsg struct {
		Unsupported	int 		`json:"unsupported"`
		Matches 	int 		`json:"matches"`
	}
	frontendMsg := FrontendMsg{0, 0}

	// Check rules number
	if len(files) == 0 {
		http.Error(w, "There are not rules to run. Please make sure you have uploaded some Sigma rule.", http.StatusInternalServerError)
	} else {


    	// Sets alert counter and alerts data variables. Then will be used to log in executionsLog.csv file
		var count int
		var newInfoAlerts [][]string
		var infoAlerts [][]string

    	// Check if executionsLog.csv exists, if not creat it
		if _, err := os.Stat("executionsLog.csv"); os.IsNotExist(err) {
			alertsCsv, err := os.Create("executionsLog.csv")
			if err != nil {
				log.Println("runAllRules: "+err.Error())
			}

			columns := []string{"Date","SigmaRule","Matches","Alert","logFileUploaded"}
			newInfoAlerts = append(newInfoAlerts, columns)

			csvWriter := csv.NewWriter(alertsCsv)
			csvWriter.WriteAll(newInfoAlerts)
			csvWriter.Flush()
			defer alertsCsv.Close()

		}

		// Start the action, read each rule file
		for _, ruleFile := range files {
			count = 0

			// Get sigma rule content info
			config, err:= getSigmaRuleInfo(ruleFile)
			if err != nil {
				log.Println("runAllRules: "+err.Error())
			}


			// Run sigmac program to obtein siem query
			out, _ := exec.Command("sigmac", "-t", Siem, ruleFile).Output()
			//fmt.Printf("%s", out)
			query := string(out)

			// NOTE: There are rules that are not supported, skip them and log it. The query from rules unsupported are "" , but the sigmac output is "An unsupported feature is required for this Sigma rule: Aggregations not implemented for this backend Feel free to contribute for fun and fame, this is open source :) -> https://github.com/Neo23x0/sigma" 

			if query == "" {

				log.Println("runAllRules: Unsupported rule:  " + ruleFile)
		
				t := time.Now()
				tFormat := t.Format("2006-01-02-15:04")
				data := []string{tFormat,ruleFile,"Unsupported",config["title"],""}
				infoAlerts = append(infoAlerts, data)

				frontendMsg.Unsupported = frontendMsg.Unsupported + 1
				
			// And if the rule is OK
			} else {

				if Siem == "graylog" {
					// Adjust query
					newQuery := strings.TrimSuffix(query, "\n") + " AND NOT agentName:SigmaShooterAgent"
					
					byteValue, err:= runRuleQueryToGraylog(days, newQuery)
					if err != nil {
						log.Println("runAllRules: "+err.Error())
					}

					// Get result into result interface
					var result map[string]interface{}
					json.Unmarshal([]byte(byteValue), &result)

					// Get number of matches returned from query sigma rule
					numEvents := int(result["total_results"].(float64))
					// If there are not matches
					if numEvents == 0 {

						t := time.Now()
						tFormat := t.Format("2006-01-02-15:04")
						data := []string{tFormat,ruleFile,"0",config["title"],""}
						infoAlerts = append(infoAlerts, data)

					// If there are matches generate an alert and send to graylog
					} else {
						// Get alerts
						messages := result["messages"].([]interface{})
						//fmt.Println(len(messages))

						// And send matches to graylog
						for i:=len(messages)-1; i >= 0; i-- {
							count = count+1

							message := messages[i].(map[string]interface{})
	  						//fmt.Println(message["message"])
							message = message["message"].(map[string]interface{})

							err = sendAlertsToGraylog(ruleFile, config, message)
							if err != nil {
								log.Println("runAllRules: "+err.Error())
							}
						}

						// Log results 
						t := time.Now()
						tFormat := t.Format("2006-01-02-15:04")

						data := []string{tFormat,ruleFile,strconv.Itoa(count),config["title"],""}
						infoAlerts = append(infoAlerts, data)

						frontendMsg.Matches = frontendMsg.Matches + count
					}

				} else if Siem == "X" {
					log.Println("In construction...")
					os.Exit(3)
				} else {
					log.Println("In construction...")
					os.Exit(3)
				}

			}
			
		}

		// Log results in executionsLog.csv
		alertsCsv, _ := os.OpenFile("executionsLog.csv", os.O_WRONLY|os.O_APPEND, 0644)
		csvWriter := csv.NewWriter(alertsCsv)
		csvWriter.WriteAll(infoAlerts)
		csvWriter.Flush()
		defer alertsCsv.Close()

	}

	var fMsg []FrontendMsg
	fMsg = append(fMsg,frontendMsg)
	data := struct {
		Err   			int          	`json:"err"`
		Msg 			[]FrontendMsg	`json:"runrule_msg"`
	}{
		0,
		fMsg,
	}
	
	ajaxResponse(w, data)
	return

}

// deleteRuleHandler: delete sigma rules from tree
func deleteRuleHandler(w http.ResponseWriter, r *http.Request){
	log.Println("Executed: deleteRuleHandler")

	type ajax struct {
		RuleId 	string `json:"ruleId"`
	}

	var reqAjax ajax

	if r.Body == nil {
		http.Error(w, "Please send a request body", 400)
		return
	}

	err := json.NewDecoder(r.Body).Decode(&reqAjax)
	if err != nil {
		http.Error(w, err.Error(), 400)
		return
	}

	if reqAjax.RuleId != "1000" {
		// Get rule path
		_, rulePath := getPathRuleNameById(reqAjax.RuleId)

		f, err := os.Stat(rulePath)
		if err != nil {
			log.Println("deleteRuleHandler: "+err.Error())
			return
		}
		if f.IsDir() {
			err = RemoveContents(rulePath)
			if err != nil {
				log.Println("deleteRuleHandler: "+err.Error())
				return
			}
		}

		// Create Backup of last rules before update them
		t := time.Now()
		dateBAK := t.Format("2006-01-02-15:04")
		targzName := "sigmaRules_"+dateBAK
		err = targzit(RulePath,RuleBakPath,targzName)
		if err != nil {
			log.Println("uploadHandler: "+err.Error())
		}

		err = os.Remove(rulePath)
		if err != nil {
			log.Println("deleteRuleHandler: "+err.Error())
			return
		}

		data := struct {
			Err   int 	 `json:"err"`
			State string `json:"state"`
		}{
			0,
			"OK",
		}

		ajaxResponse(w, data)
		return
	} else {
		http.Error(w, "Can't delete rule root path. For deleting all rules, click \"Delete rules\" button.", 400)
		return
	}

}

// deleteHandler: delete all sigma rules
func deleteHandler(w http.ResponseWriter, r *http.Request){
	log.Println("Executed: deleteHandler")

	// Root rule path is node with id 1000
	_, rulePath := getPathRuleNameById("1000")

	// Create Backup of last rules before update them
	t := time.Now()
	dateBAK := t.Format("2006-01-02-15:04")
	targzName := "sigmaRules_"+dateBAK
	err := targzit(RulePath,RuleBakPath,targzName)
	if err != nil {
		log.Println("uploadHandler: "+err.Error())
	}

	err = RemoveContents(rulePath)
	if err != nil {
		log.Println("deleteHandler: "+err.Error())
		return
	}

	http.Redirect(w, r, "/", http.StatusFound)
	return

	
}

// rulesCountHandler: count number of sigma rules charged
func rulesCountHandler(w http.ResponseWriter, r *http.Request){
	var total int
	var err error

	// Take sigma rules
	files, err := FilePathWalkDir(RulePath)
	if err != nil {
		log.Println("rulesCountHandler: "+err.Error())
	}

	var rulesYml []string
	for _, file :=range files {
		if strings.HasSuffix(file,".yml") {
			rulesYml = append(rulesYml, file)
		}
	}

	total = len(rulesYml)

	data := struct {
		Err   int `json:"err"`
		Total int `json:"total"`
	}{
		0,
		total,
	}

	ajaxResponse(w, data)
	return
	
}


// testRulesHandler: run sigma rules and show results in frontend
func testRulesHandler(w http.ResponseWriter, r *http.Request){
	log.Println("Executed: testRulesHandler")

	// Create result variables
	type testsResult struct {
		RuleName 		string	`json:"rule_name"`
		NumAlerts 		string	`json:"num_alerts"`
	}
	var resultTestHandler testsResult
	var resultsTestHandler []testsResult


	// get sigma rules
	files, err := FilePathWalkDir(RulePath)
	if err != nil {
		log.Println("testRulesHandler: "+err.Error())
	}

	// Check rules number
	if len(files) == 0 {
		http.Error(w, "There are not rules to run. Please make sure you have uploaded some Sigma rule.", http.StatusInternalServerError)
	} else {


		// Start the action, read each rule file
		for _, ruleFile := range files {

			// Run sigmac program to obtein siem query
			out, _ := exec.Command("sigmac", "-t", Siem, ruleFile).Output()
			//fmt.Printf("%s", out)
			query := string(out)

			// NOTE: There are rules that are not supported, skip them and log it. The query from rules unsupported are "" , but the sigmac output is "An unsupported feature is required for this Sigma rule: Aggregations not implemented for this backend Feel free to contribute for fun and fame, this is open source :) -> https://github.com/Neo23x0/sigma" 

			if query == "" {

				log.Println("testRulesHandler: Unsupported rule =>  " + ruleFile)

				// Save results
				resultTestHandler.RuleName = ruleFile
				resultTestHandler.NumAlerts = "Unsupported"
				resultsTestHandler = append(resultsTestHandler,resultTestHandler)


			// And if the rule is OK
			} else {

				if Siem == "graylog" {
					// Adjust query
					newQuery := strings.TrimSuffix(query, "\n") + " AND NOT agentName:SigmaShooterAgent"
					
					byteValue, err:= runRuleQueryToGraylog(1, newQuery)
					if err != nil {
						log.Println("testRulesHandler: "+err.Error())
					}

					// Get result into result interface
					var result map[string]interface{}
					json.Unmarshal([]byte(byteValue), &result)

					// Get number of matches
					numEvents := int(result["total_results"].(float64))
					
					// Save results
					resultTestHandler.RuleName = ruleFile
					resultTestHandler.NumAlerts = strconv.Itoa(numEvents)
					resultsTestHandler = append(resultsTestHandler,resultTestHandler)

				} else if Siem == "X" {
					log.Println("In construction...")
					os.Exit(3)
				} else {
					log.Println("In construction...")
					os.Exit(3)
				}
			}
		}
	}

	// Send the result back to JS
	resultFunc := struct {
		Err   				int          	`json:"err"`
		ResultsTest 		[]testsResult 	`json:"resultsTest"`
	}{
		0,
		resultsTestHandler,
	}

	ajaxResponse(w, resultFunc)
	return

}


// testRuleFileHandler: run sigma rule file and show results in frontend
// NOTE: the error is shown in js alerts to not lose rule data
func testRuleFileHandler(rw http.ResponseWriter, req *http.Request) {
	log.Println("Executed: testRuleFileHandler")

	type ajax struct {
		RuleName 	string `json:"ruleName"`
		RuleFile	string `json:"ruleBody"`
	}

	var reqAjax ajax

	err := json.NewDecoder(req.Body).Decode(&reqAjax)
	if err != nil {
		// Send the result back to JS
		resultFunc := struct {
			Err   				int          	`json:"err"`
			ErrMsg	 			string 		 	`json:"errMsg"`
		}{
			0,
			"Bad file content",
		}
		ajaxResponse(rw, resultFunc)
		return
	}

	// Check file extension
	fnameRegex := regexp.MustCompile(`.yml$`)
	if !fnameRegex.Match([]byte(reqAjax.RuleName)) {
		// Send the result back to JS
		resultFunc := struct {
			Err   				int          	`json:"err"`
			ErrMsg	 			string 		 	`json:"errMsg"`
		}{
			0,
			"File must be a .yml file",
		}
		ajaxResponse(rw, resultFunc)
		return
	}

	// Check if file already exists
	files, err := FilePathWalkDir(RulePath)
	for _, file := range files {
		fileSplit := strings.Split(file,"/")
		ymlFile := fileSplit[len(fileSplit)-1]
		if reqAjax.RuleName == ymlFile {
			// Send the result back to JS
			resultFunc := struct {
				Err   				int          	`json:"err"`
				ErrMsg	 			string 		 	`json:"errMsg"`
			}{
				0,
				"There is already a rule with the same name. Please, enter a valid name.",
			}
			ajaxResponse(rw, resultFunc)
			return
		}
	}

	ruleContent := []byte(reqAjax.RuleFile)
    err = ioutil.WriteFile("tmp/"+reqAjax.RuleName, ruleContent, 0644)
    if err != nil {
		log.Println("testRuleFileHandler: "+err.Error())
		return
	}


	// Create result variables
	type testsResult struct {
		RuleName 		string	`json:"rule_name"`
		NumAlerts 		string	`json:"num_alerts"`
	}
	var resultTestHandler testsResult
	var resultsTestHandler []testsResult

	// Run sigmac program to obtein siem query
	out, _ := exec.Command("sigmac", "-t", Siem, "tmp/"+reqAjax.RuleName).Output()
	//fmt.Printf("%s", out)
	query := string(out)

	// NOTE: There are rules that are not supported, skip them and log it. The query from rules unsupported are "" , but the sigmac output is "An unsupported feature is required for this Sigma rule: Aggregations not implemented for this backend Feel free to contribute for fun and fame, this is open source :) -> https://github.com/Neo23x0/sigma" 

	if query == "" {

		log.Println("testRuleFileHandler: Unsupported rule =>  " + reqAjax.RuleName)

		// Save results
		resultTestHandler.RuleName = reqAjax.RuleName
		resultTestHandler.NumAlerts = "Unsupported"
		resultsTestHandler = append(resultsTestHandler,resultTestHandler)

	// And if the rule is OK
	} else {

		if Siem == "graylog" {
			// Adjust query
			newQuery := strings.TrimSuffix(query, "\n") + " AND NOT agentName:SigmaShooterAgent"

			byteValue, err:= runRuleQueryToGraylog(1, newQuery)
			if err != nil {
				log.Println("testRuleFileHandler: "+err.Error())
			}

			// Get result into result interface
			var result map[string]interface{}
			json.Unmarshal([]byte(byteValue), &result)

			// Get number of matches 
			numEvents := int(result["total_results"].(float64))
			
			// Save results
			resultTestHandler.RuleName = reqAjax.RuleName
			resultTestHandler.NumAlerts = strconv.Itoa(numEvents)
			resultsTestHandler = append(resultsTestHandler,resultTestHandler)
		} else if Siem == "X" {
			log.Println("In construction...")
			os.Exit(3)
		} else {
			log.Println("In construction...")
			os.Exit(3)
		}
	}

	if checkNamePathRule(reqAjax.RuleName) {
		err = os.Remove("tmp/"+reqAjax.RuleName)
		if err != nil {
			log.Println("testRuleFileHandler: "+err.Error())
			return
		}
	} else {
		log.Println("testRuleFileHandler: Invalid value, possible attack. Value entered: "+reqAjax.RuleName)
	}
	
	// Send the result back to JS
	resultFunc := struct {
		Err   				int          	`json:"err"`
		ResultsTest 		[]testsResult 	`json:"resultsTest"`
		ErrMsg	 			string 		 	`json:"errMsg"`
	}{
		0,
		resultsTestHandler,
		"",
	}

	ajaxResponse(rw, resultFunc)
	return

}

// testRuleManualHandler: run sigma manual rule and show results in frontend
// NOTE: the error is shown in js alerts to not lose rule data
func testRuleManualHandler(rw http.ResponseWriter, req *http.Request) {
	log.Println("Executed: testRuleManualHandler")

	type ajax struct {
		RuleName 	string `json:"ruleName"`
		RuleBody	string `json:"ruleBody"`
	}

	var reqAjax ajax

	err := json.NewDecoder(req.Body).Decode(&reqAjax)
	if err != nil {
		// Send the result back to JS
		resultFunc := struct {
			Err   				int          	`json:"err"`
			ErrMsg	 			string 		 	`json:"errMsg"`
		}{
			0,
			"Bad file content",
		}
		ajaxResponse(rw, resultFunc)
		return
	}

	if reqAjax.RuleName == "" || reqAjax.RuleBody == "" {
		// Send the result back to JS
		resultFunc := struct {
			Err   				int          	`json:"err"`
			ErrMsg	 			string 		 	`json:"errMsg"`
		}{
			0,
			"Name or body empty. Please send a valid file",
		}
		ajaxResponse(rw, resultFunc)
		return
	}

	// Check file extension
	fnameRegex := regexp.MustCompile(`.yml$`)
	if !fnameRegex.Match([]byte(reqAjax.RuleName)) {
		// Send the result back to JS
		resultFunc := struct {
			Err   				int          	`json:"err"`
			ErrMsg	 			string 		 	`json:"errMsg"`
		}{
			0,
			"File must be a .yml file",
		}
		ajaxResponse(rw, resultFunc)
		return
	}

	// Check if file have already exists
	files, err := FilePathWalkDir(RulePath)
	for _, file := range files {
		fileSplit := strings.Split(file,"/")
		ymlFile := fileSplit[len(fileSplit)-1]
		if reqAjax.RuleName == ymlFile {
			// Send the result back to JS
			resultFunc := struct {
				Err   				int          	`json:"err"`
				ErrMsg	 			string 		 	`json:"errMsg"`
			}{
				0,
				"There is already a rule with the same name. Please, enter a valid name.",
			}
			ajaxResponse(rw, resultFunc)
			return
		}
	}

	ruleContent := []byte(reqAjax.RuleBody)
    err = ioutil.WriteFile("tmp/"+reqAjax.RuleName, ruleContent, 0644)
    if err != nil {
		log.Println("testRuleManualHandler: "+err.Error())
		return
	}

	// Create result variables
	type testsResult struct {
		RuleName 		string	`json:"rule_name"`
		NumAlerts 		string	`json:"num_alerts"`
	}
	var resultTestHandler testsResult
	var resultsTestHandler []testsResult


	// Run sigmac program to obtein siem query
	out, _ := exec.Command("sigmac", "-t", Siem, "tmp/"+reqAjax.RuleName).Output()
	//fmt.Printf("%s", out)
	query := string(out)

	// NOTE: There are rules that are not supported, skip them and log it. The query from rules unsupported are "" , but the sigmac output is "An unsupported feature is required for this Sigma rule: Aggregations not implemented for this backend Feel free to contribute for fun and fame, this is open source :) -> https://github.com/Neo23x0/sigma" 

	if query == "" {

		log.Println("testRuleManualHandler: Unsupported rule =>  " + reqAjax.RuleName)

		// Save results
		resultTestHandler.RuleName = reqAjax.RuleName
		resultTestHandler.NumAlerts = "Unsupported"
		resultsTestHandler = append(resultsTestHandler,resultTestHandler)

	// And if the rule is OK
	} else {

		if Siem == "graylog" {
			// Adjust query
			newQuery := strings.TrimSuffix(query, "\n") + " AND NOT agentName:SigmaShooterAgent"

			byteValue, err:= runRuleQueryToGraylog(1, newQuery)
			if err != nil {
				log.Println("testRuleManualHandler: "+err.Error())
			}

			// Get result into result interface
			var result map[string]interface{}
			json.Unmarshal([]byte(byteValue), &result)

			// Get number of matches 
			numEvents := int(result["total_results"].(float64))
			
			// Save results
			resultTestHandler.RuleName = reqAjax.RuleName
			resultTestHandler.NumAlerts = strconv.Itoa(numEvents)
			resultsTestHandler = append(resultsTestHandler,resultTestHandler)

		} else if Siem == "X" {
			log.Println("In construction...")
			os.Exit(3)
		} else {
			log.Println("In construction...")
			os.Exit(3)
		}
	}

	if checkNamePathRule(reqAjax.RuleName) {
		err = os.Remove("tmp/"+reqAjax.RuleName)
		if err != nil {
			log.Println("testRuleManualHandler: "+err.Error())
			return
		}
	} else {
		log.Println("testRuleManualHandler: Invalid value, possible attack. Value entered: "+reqAjax.RuleName)
	}
	
	// Send the result back to JS
	resultFunc := struct {
		Err   				int          	`json:"err"`
		ResultsTest 		[]testsResult 	`json:"resultsTest"`
		ErrMsg	 			string 		 	`json:"errMsg"`
	}{
		0,
		resultsTestHandler,
		"",
	}

	ajaxResponse(rw, resultFunc)
	return

}
