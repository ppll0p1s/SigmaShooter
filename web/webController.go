package web

import (
	//"fmt"

	"html/template"
	"net/http"
	"path"
	"regexp"
	"os"
	"path/filepath"
	"log"
	"strings"
	"encoding/json"
	"encoding/csv"
	"time"
	"strconv"
	"bufio"
	"io/ioutil"
)


// indexHandler: return the main view without data
func indexHandler(rw http.ResponseWriter, req *http.Request) {
	lp := path.Join("views", "layout.html")
	fp := path.Join("views", "index.html")

	tmpl, err := template.ParseFiles(lp, fp)
	if err != nil {
		http.Error(rw, err.Error(), http.StatusInternalServerError)
		return
	}

	templateData := struct {
		Ver   string
		Token string
	}{
		Version,
		"0123456789abcdef",
	}

	if err := tmpl.Execute(rw, templateData); err != nil {
		http.Error(rw, err.Error(), http.StatusInternalServerError)
		return
	}
}

// logstosiemHandler: return the logs to siem view
func logstosiemHandler(rw http.ResponseWriter, req *http.Request) {
	lp := path.Join("views", "layout.html")
	fp := path.Join("views", "logstosiem.html")

	tmpl, err := template.ParseFiles(lp, fp)
	if err != nil {
		http.Error(rw, err.Error(), http.StatusInternalServerError)
		return
	}

	templateData := struct {
		Ver   string
		Token string
	}{
		Version,
		"0123456789abcdef",
	}

	if err := tmpl.Execute(rw, templateData); err != nil {
		http.Error(rw, err.Error(), http.StatusInternalServerError)
		return
	}
}


// getFolderList: get sigma rules folder list, folder's names and rules count inside each folder
func getFolderList(rw http.ResponseWriter, req *http.Request) {
	var rulesFolder []string 

	err := filepath.Walk(RulePath,
		func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}

			paths := strings.Split(path,"\n")

			var rules []string
			for _, p := range paths {
				if strings.Contains(p,".yml") {
					rules = append(rules,p)
				}
			}

			for _, r := range rules {
				folder := strings.Split(r,"/")
				rule := folder[len(folder)-1]

				rule = strings.TrimRight(r,rule)
				rulesFolder = append(rulesFolder, rule)
			}

			return nil
	})

	if err != nil {
		log.Println("getFolderList: "+err.Error())
	}

	var rulesFolderUniq []string

	for i:=0; i<len(rulesFolder); i++ {

		check := false
		istring := rulesFolder[i]

		for j:=0; j<len(rulesFolderUniq); j++ {
			jstring := rulesFolderUniq[j]
			if istring == jstring {
				check = true
			} 
			
		}
		if !check {
			rulesFolderUniq = append(rulesFolderUniq,rulesFolder[i])
		}

	}

	var rulesCont []int
	var cont int
	for _, dir := range rulesFolderUniq {
		cont = 0
		for _, dir2 := range rulesFolder {
			if dir == dir2 {
				cont++
			}
		}
		rulesCont = append(rulesCont, cont)
	}

	type RulesFolder struct {
		FolderName	string 		`json:"folder_name"`
		RulesNumber	int 		`json:"rules_number"`
	}

	var rulesfolders []RulesFolder 
	var rfitem RulesFolder 
	for i, _ := range rulesFolderUniq {
		rfitem.FolderName = rulesFolderUniq[i]
		rfitem.RulesNumber = rulesCont[i]
		rulesfolders = append(rulesfolders,rfitem)
	}

	// Order by rulesNumber from highest to lower to improve chartTypeRules
	var rulesfoldersOrder []RulesFolder
	var itemOrdered RulesFolder

	if len(rulesfolders) == 0{
		itemOrdered.FolderName = "rules/"
		itemOrdered.RulesNumber = 0
		rulesfoldersOrder = append(rulesfoldersOrder,itemOrdered)
	} else {
		for len(rulesfolders)>0 {
			min := rulesfolders[0].RulesNumber
			indexMin := 0
			for j, ruleType := range rulesfolders {
				if ruleType.RulesNumber <= min {
					min = ruleType.RulesNumber
					indexMin = j
				}
			}
			itemOrdered.FolderName = rulesfolders[indexMin].FolderName
			itemOrdered.RulesNumber = rulesfolders[indexMin].RulesNumber
			rulesfoldersOrder = append(rulesfoldersOrder,itemOrdered)

			// And now, delete rulesfoldersOrder[j]
			rulesfolders = append(rulesfolders[:indexMin], rulesfolders[indexMin+1:]...)
		}
	}

	data := struct {
		Err   			int          	`json:"err"`
		Folders 		[]RulesFolder 	`json:"rulesfolders"`
	}{
		0,
		rulesfoldersOrder,
	}

	ajaxResponse(rw, data)
	return
}

// getLastAlertsCountByDay: get alerts of last 10 days from executionsLog.csv file
func getLastAlertsCountByDay(rw http.ResponseWriter, req *http.Request) {

	// if executionsLog.csv exist send last alerts
	if _, err := os.Stat("executionsLog.csv"); !os.IsNotExist(err) {
		// Open CSV
		csvFile, _ := os.Open("executionsLog.csv")
		reader := csv.NewReader(bufio.NewReader(csvFile))
		
		// Read CSV data
		var data [][]string
		data, err := reader.ReadAll()
		if err != nil {
			log.Println("getLastAlertsCountByDay: "+err.Error())
		}

		//fmt.Println(data[11])

		// Create result variables
		type alertsDay struct {
			Day 	string		`json:"day_alerts"`
			Count 	int			`json:"count_alerts"`
		}
		var alerts []alertsDay
		
		today := time.Now()
		// loop from today until last 10 days
		for i, j := len(data)-1, 0; j<10; j++ {

			subtrackDay := today.AddDate(0, 0, -j)
			subtrackDayFormat := subtrackDay.Format("2006-01-02")

			// Count number of alerts/matches per day
			// The result of alerts will be like this:
			// 2019-02-23 1  (the day 23 all the rules only matched 1)
			count := 0
			if strings.Contains(data[i][0],subtrackDayFormat) {
				
				for strings.Contains(data[i][0],subtrackDayFormat) {
					matches := data[i][2]
					if matches == "Unsupported" {
						i--
					} else {
						numMatches, _ := strconv.Atoi(matches)
						count = count + numMatches
						i--
					}
				}
				var alert alertsDay
				alert.Day = subtrackDayFormat
				alert.Count = count
				alerts = append(alerts,alert)

			} else {
				var alert alertsDay
				alert.Day = subtrackDayFormat
				alert.Count = count
				alerts = append(alerts,alert)
			}
		}

		// Turn arround the alerts slice (this is to improve chart design..)
		var alertsChart []alertsDay
		for i:=len(alerts)-1; i>=0; i-- {
			alertsChart = append(alertsChart, alerts[i])
		}

		// Send the result back to JS
		alertsData := struct {
			Err   				int          	`json:"err"`
			AlertsLastDays 		[]alertsDay 	`json:"alertslastdays"`
		}{
			0,
			alertsChart,
		}

		ajaxResponse(rw, alertsData)
		return
	// if not, send json with 0 alerts
	} else {
		// Create result variables
		type alertsDay struct {
			Day 	string		`json:"day_alerts"`
			Count 	int			`json:"count_alerts"`
		}
		var alert alertsDay
		var alerts []alertsDay
		
		today := time.Now()
		// loop from today until last 10 days
		for j :=  10; j>=0; j-- {

			subtrackDay := today.AddDate(0, 0, -j)
			subtrackDayFormat := subtrackDay.Format("2006-01-02")

			alert.Day = subtrackDayFormat
			alert.Count = 0
			alerts = append(alerts,alert)

		}

		// Send the result back to JS
		alertsData := struct {
			Err   				int          	`json:"err"`
			AlertsLastDays 		[]alertsDay 	`json:"alertslastdays"`
		}{
			0,
			alerts,
		}

		ajaxResponse(rw, alertsData)
		return
	}

}

// getJsonRulesTree: get json rules tree from rulePath

// Lets define strucs will be used in this func

type StateTree struct {
	Opened 		 bool		`json:"opened"`
}

type RuleTree struct {
	Id 			 int    	`json:"id"`
	Text         string    	`json:"text"`
	State 		 StateTree 	`json:"state"`
	Type 		 string 	`json:"type"`
	Children     []*File   	`json:"children"`
}

type File struct {
	Id 			 int    	`json:"id"`
	Text         string    	`json:"text"`
    // We will remove Path lines from final json, we dont need it in jsTree and this field is not in the library. The result will be a RuleTree variable
	Path         string    	`json:"Path"`
	State 		 StateTree 	`json:"state"`
	Type 		 string 	`json:"type"`
	Children     []*File   	`json:"children"`
}

func getJsonRulesTree(rw http.ResponseWriter, req *http.Request) {
	id := 1000
	path := RulePath
	pathRoot := path
	rootOSFile, _ := os.Stat(path)
    rootFile := toFile(id, rootOSFile, path, pathRoot) //start with root file
    stack := []*File{rootFile}


    // At the end, we will build a rules.db file
    // add first element
    rulesdb := strconv.Itoa(rootFile.Id) + "," + rootFile.Text + "," + rootFile.Path + "\n"

    for len(stack) > 0 { //until stack is empty,
        file := stack[len(stack)-1] //pop entry from stack
        stack = stack[:len(stack)-1]
        children, _ := ioutil.ReadDir(file.Path) //get the children of entry
        for _, chld := range children {          //for each child
            id = id+1

            child := toFile(id, chld, filepath.Join(file.Path, chld.Name()), pathRoot) //turn it into a File object
            rulesdb += strconv.Itoa(child.Id) + "," + child.Text + "," + child.Path + "\n"
            file.Children = append(file.Children, child)                 //append it to the children of the current file popped
            stack = append(stack, child)                                 //append the child to the stack, so the same process can be run again
        }
    }

    output, _ := json.MarshalIndent(rootFile, "", "     ")
    outputStr := strings.Split(string(output), "\n")

    var finalJson string
    for _, line :=range outputStr {
    	if !strings.Contains(line,"\"Path\":") {
    		finalJson += line+"\n"
    	}
    }

    // Lets unmarshal the json tree to RuleTree struct
    var finalJsonInt RuleTree
    _ = json.Unmarshal([]byte(finalJson),&finalJsonInt)

    //fmt.Println(finalJson)

    // Save rules.db
    content := []byte(rulesdb)
    err := ioutil.WriteFile("rules.db", content, 0644)
    if err != nil {
    	log.Println("getJsonRulesTree: "+err.Error())
    }

	// Send the result back to JS
    ruleListingTree := struct {
    	Err   				int          	`json:"err"`
    	RuleFileTree 		RuleTree		`json:"rulesTree"`
    }{
    	0,
    	finalJsonInt,
    }

    ajaxResponse(rw, ruleListingTree)
    return


}

// toFile: complet json for each rule/folder called in getJsonRulesTree func
func toFile(id int, file os.FileInfo, path, pathRoot string) *File {

	// Set state opened value
	stateField := StateTree{
		Opened: 	false,
	}
	if path == pathRoot {
		stateField.Opened  = true
	}

	// Set text value (if is a folder, get numer of rules there are betwenn brackets), and icons type
	rules, err := FilePathWalkDir(path)
	if err != nil {
		log.Println("getJsonRulesTree: toFile: "+err.Error())
	}

	var text string
	var typeIcon string
	if file.IsDir() && !stateField.Opened {
		text = file.Name()+ " ("+strconv.Itoa(len(rules))+")"
		typeIcon = "folder"
	} else if file.IsDir() && stateField.Opened {
		text = file.Name()+ " ("+strconv.Itoa(len(rules))+")"
		typeIcon = "folder-open"
	}else {
		text = file.Name()
		typeIcon = "yml"
	}

	JSONFile := File{
		Id:     id,
		Text:     text,
		Path:     path,
		State: 	  stateField,
		Type: 	  typeIcon,
		Children: []*File{},
	}

	//fmt.Println(JSONFile)

	return &JSONFile
}


// uploadEditRule: upload single Sigma rule
func uploadEditRule(rw http.ResponseWriter, req *http.Request) {
	log.Println("Executed: uploadEditRule")

	ruleName := req.FormValue("ruleName")
	ruleContent := req.FormValue("ruleContent")
	rulePath := req.FormValue("uploadRulePath2")

	if req.Body == nil {
		http.Error(rw, "Please send a request body", 400)
		return
	}

	// Check file extension
	fnameRegex := regexp.MustCompile(`.yml$`)
	if !fnameRegex.Match([]byte(ruleName)) {
		http.Error(rw, "File must be a .yml file", http.StatusInternalServerError)
		return
	}

	// Check if file have already exists
	files, err := FilePathWalkDir(RulePath)
	if err != nil {
		log.Println("uploadEditRule: toFile: "+err.Error())
	}
	for _, file := range files {
		fileSplit := strings.Split(file,"/")
		ymlFile := fileSplit[len(fileSplit)-1]
		if ruleName == ymlFile {
			http.Error(rw, "There is already a rule with the same name. Please, enter a valid name.", http.StatusInternalServerError)
			return
		}
	}

	ruleContentByte := []byte(ruleContent)
    err = ioutil.WriteFile(rulePath+ruleName, ruleContentByte, 0644)
    if err != nil {
		log.Println("uploadEditRule: "+err.Error())
		return
	}

	http.Redirect(rw, req, "/", http.StatusFound)
	return

}

// getLastExecutionsLogs: show in "Executions last day" tab SigmaShooter executions of last day
func getLastExecutionsLogs(w http.ResponseWriter, r *http.Request){

	// Create result variables
	type logsLastDay struct {
		Date 		string		`json:"date_log"`
		SigmaRule 	string		`json:"sigmaRule_log"`
		Matches  	string		`json:"matches_log"`
		Alert 	  	string		`json:"alert_log"`
		LogFile  	string		`json:"logfile_log"`
	}
	var loglast logsLastDay
	var logs []logsLastDay

	// continue if executionsLog.csv exist
	if _, err := os.Stat("executionsLog.csv"); !os.IsNotExist(err) {
		// Open CSV
		csvFile, _ := os.Open("executionsLog.csv")
		reader := csv.NewReader(bufio.NewReader(csvFile))
		
		// Read CSV data
		var data [][]string
		data, err := reader.ReadAll()
		if err != nil {
			log.Println("getLastExecutionsLogs: "+err.Error())
		}
		
		today := time.Now()

		todayFormat := today.Format("2006-01-02")

		i := len(data)-1
		if strings.Contains(data[i][0],todayFormat) {

			for strings.Contains(data[i][0],todayFormat) {
				loglast.Date = data[i][0]
				loglast.SigmaRule = data[i][1]
				loglast.Matches = data[i][2]
				loglast.Alert = data[i][3]
				/*
				if data[i][3]!=""{
					loglast.Alert = "("+data[i][3]+")"
				} else {
					loglast.Alert = data[i][3]
				}
				*/
				loglast.LogFile = data[i][4]
				logs = append(logs,loglast)
				i--
			}

		}
	} 

	if len(logs) == 0 {
		loglast.Date = "0"
		loglast.SigmaRule = "0"
		loglast.Matches = "0"
		loglast.LogFile = ""
		loglast.Alert = ""
		logs = append(logs,loglast)
	}

	// Send the result back to JS
	logsData := struct {
		Err   				int          	`json:"err"`
		ExecLogs 			[]logsLastDay 	`json:"execLogs"`
	}{
		0,
		logs,
	}

	ajaxResponse(w, logsData)
	return

}

// downloadExecLogs: serve executionsLog.csv
func downloadExecLogs(w http.ResponseWriter, r *http.Request){
	log.Println("Executed: downloadExecLogs")
	w.Header().Set("Content-Type", "application/csv")
	w.Header().Set("Content-Disposition", "attachment; filename=executionsLog.csv")
	http.ServeFile(w, r, "executionsLog.csv")
}

// infoEditRule: show info Sigma rule in edit modal
func infoEditRule(rw http.ResponseWriter, req *http.Request) {
	log.Println("Executed: infoEditRule")

	type ajax struct {
		RuleId 	string `json:"ruleId"`
	}

	var reqAjax ajax

	if req.Body == nil {
		http.Error(rw, "Please send a request body", 400)
		return
	}

	err := json.NewDecoder(req.Body).Decode(&reqAjax)
	if err != nil {
		http.Error(rw, err.Error(), 400)
		return
	}


	type ruleData struct {
		Name 		string		`json:"ruleNameInfo"`
		Content 	string		`json:"ruleContentInfo"`
	}	

	// Get rule content
	_, rulePath := getPathRuleNameById(reqAjax.RuleId)

    dat, err := ioutil.ReadFile(rulePath)
    if err != nil {
		log.Println("infoEditRule: "+err.Error())
	}

	// Prepare the data response
	var infoRule ruleData
	infoRule.Name = rulePath
	infoRule.Content = string(dat)
	var infoRules []ruleData
	infoRules = append(infoRules, infoRule)

	// Send the result back to JS
	infoRuleData := struct {
		Err   				int          	`json:"err"`
		InfoRuleData		[]ruleData 		`json:"infoRuleData"`
	}{
		0,
		infoRules,
	}

	ajaxResponse(rw, infoRuleData)
	return

}

// newNodeName: change name to the dbclicked node
func newNodeName(rw http.ResponseWriter, req *http.Request) {
	log.Println("Executed: newNodeName")

	type ajax struct {
		RuleId 	string `json:"ruleId"`
		FolderNewName string `json:"folderNewName"`
	}

	var reqAjax ajax

	if req.Body == nil {
		http.Error(rw, "Please send a request body", 400)
		return
	}

	err := json.NewDecoder(req.Body).Decode(&reqAjax)
	if err != nil {
		http.Error(rw, err.Error(), 400)
		return
	}

	// Get rule info
	_, rulePath := getPathRuleNameById(reqAjax.RuleId)

	// Rename rule with the new name
	resPath := strings.Split(rulePath,"/")
	// New name
	nName := strings.Replace(rulePath,resPath[len(resPath)-1],reqAjax.FolderNewName,-1)

	// Sanitize new name reqAjax.FolderNewName
	if checkNameFolder(reqAjax.FolderNewName) {
		err = os.Rename(rulePath, nName)
		if err != nil {
			log.Println("newNodeName: "+err.Error())
		}
	} else {
		log.Println("newNodeName: Invalid value, possible attack. Value entered: "+reqAjax.FolderNewName)
	}

	return
}

// editRule: save changes made in edit modal
func editRule(rw http.ResponseWriter, req *http.Request) {
	log.Println("Executed: editRule")

	ruleName := req.FormValue("nameFileEdit")
	ruleNameNew := req.FormValue("nameFileEditNew")
	ruleContent := req.FormValue("ruleContentEdit")

	if req.Body == nil {
		http.Error(rw, "Please send a request body", 400)
		return
	}

	// Check file extension
	fnameRegex := regexp.MustCompile(`.yml$`)
	if !fnameRegex.Match([]byte(ruleNameNew)) {
		http.Error(rw, "File must be a .yml file", http.StatusInternalServerError)
		return
	}

	// Check if file have already exists
	files, err := FilePathWalkDir(RulePath)
	if err != nil {
		log.Println("editRule: toFile: "+err.Error())
	}
	for _, file := range files {
		fileSplit := strings.Split(file,"/")
		ymlFile := fileSplit[len(fileSplit)-1]
		if ruleName == ymlFile {
			http.Error(rw, "There is already a rule with the same name. Please, enter a valid name.", http.StatusInternalServerError)
			return
		}
	}

	// Check if user has changed the path and check if the new path exists
	if ruleName != ruleNameNew {
		newrulename := strings.Split(ruleNameNew,"/")
		newPath := strings.Replace(ruleNameNew,newrulename[len(newrulename)-1],"",-1)
		_, err := os.Stat(newPath)
		if os.IsNotExist(err) {
			http.Error(rw, "Path does not exist. Please, enter a valid path.", http.StatusInternalServerError)
			return
		} else {
			// Sanitize new name reqAjax.FolderNewName
			if checkNamePathRule(ruleName) && checkNamePathRule(ruleNameNew){
				err = os.Rename(ruleName, ruleNameNew)
				if err != nil {
					log.Println("editRule: "+err.Error())
				}

				ruleContentByte := []byte(ruleContent)
				err := ioutil.WriteFile(ruleNameNew, ruleContentByte, 0644)
			    if err != nil {
					log.Println("editRule: "+err.Error())
					return
				}
			} else {
				log.Println("editRule: Invalid value, possible attack. Value entered: "+ruleName+"\n and: "+ruleNameNew)
			}
		}
	} else {
		ruleContentByte := []byte(ruleContent)
	    err := ioutil.WriteFile(ruleName, ruleContentByte, 0644)
	    if err != nil {
			log.Println("editRule: "+err.Error())
			return
		}
	}

	http.Redirect(rw, req, "/", http.StatusFound)
	return

}


// moveDnd: apply drag and drop actions on rule set
func moveDnd(rw http.ResponseWriter, req *http.Request) {
	log.Println("Executed: moveDnd")

	type ajax struct {
		NodeDrag 		string `json:"nodeDrag"`
		NodeToDrop 	 	string `json:"nodeToDrop"`
	}

	var reqAjax ajax

	if req.Body == nil {
		http.Error(rw, "Please send a request body", 400)
		return
	}

	err := json.NewDecoder(req.Body).Decode(&reqAjax)
	if err != nil {
		http.Error(rw, err.Error(), 400)
		return
	}

	// Get rule info
	_, rulePathDrag := getPathRuleNameById(reqAjax.NodeDrag)
	_, rulePathToDrop := getPathRuleNameById(reqAjax.NodeToDrop)

	//fmt.Println(rulePathDrag+" will be moved to "+rulePathToDrop)

	// Not needed to santize
	err = os.Rename(rulePathDrag, rulePathToDrop)
	if err != nil {
		log.Println("moveDnd: "+err.Error())
	}

	return
}

// addFolder: add new folder in rule tree
func addFolder(rw http.ResponseWriter, req *http.Request) {
	log.Println("Executed: addFolder")

	type ajax struct {
		RuleId 	string `json:"ruleId"`
	}

	var reqAjax ajax

	if req.Body == nil {
		http.Error(rw, "Please send a request body", 400)
		return
	}

	err := json.NewDecoder(req.Body).Decode(&reqAjax)
	if err != nil {
		http.Error(rw, err.Error(), 400)
		return
	}

	// Get rule info
	_, rulePath := getPathRuleNameById(reqAjax.RuleId)

	if err = os.MkdirAll(rulePath+"/New folder", 0755); err != nil {
		log.Println("addFolder: "+err.Error())
	}

	if err != nil {
		log.Println("addFolder: "+err.Error())
		return
	}

	return
}

// getPathToAddRule: get rule path to show in frontend uploadRuleModal where new rule added by user will be saved to
func getPathToAddRule(rw http.ResponseWriter, req *http.Request) {
	log.Println("Executed: getPathToAddRule")

	type ajax struct {
		RuleId 	string `json:"ruleId"`
	}

	var reqAjax ajax

	if req.Body == nil {
		http.Error(rw, "Please send a request body", 400)
		return
	}

	err := json.NewDecoder(req.Body).Decode(&reqAjax)
	if err != nil {
		http.Error(rw, err.Error(), 400)
		return
	}

	// Get rule info
	_, rulePath := getPathRuleNameById(reqAjax.RuleId)

	type ruleData struct {
		Path 		string		`json:"rulePath"`
	}	

	// Prepare the data response
	var infoRule ruleData
	infoRule.Path = rulePath
	var infoRules []ruleData
	infoRules = append(infoRules, infoRule)

	// Send the result back to JS
	infoRuleData := struct {
		Err   				int          	`json:"err"`
		InfoRuleData		[]ruleData 		`json:"infoRuleData"`
	}{
		0,
		infoRules,
	}

	ajaxResponse(rw, infoRuleData)
	return

}


// getRootRulePath: get rule root path to show in frontend
func getRootRulePath(w http.ResponseWriter, r *http.Request){

	// continue if rules.db exist
	if _, err := os.Stat("rules.db"); !os.IsNotExist(err) {

		file, err := os.Open("rules.db")
	    if err != nil {
	        log.Println("getRootRulePath: "+err.Error())
	    }
	    defer file.Close()

	    // read rule root path, first line
	    scanner := bufio.NewScanner(file)
	    path := ""
	    for scanner.Scan() {
	    	line := strings.Split(scanner.Text(),",")
	    	path = line[2]
	       	break
	    }

	    if err := scanner.Err(); err != nil {
	        log.Println("getRootRulePath: "+err.Error())
	    }

		data := struct {
			Err   int 		`json:"err"`
			Path  string 	`json:"path"`
		}{
			0,
			path,
		}

		ajaxResponse(w, data)
		return
	}
	return
	
}
