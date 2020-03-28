package web

import (
	//"fmt"

	"net/http"
	"regexp"
	"log"
	"os"
	"io"
	"time"
	"strconv"
	"encoding/csv"
	"encoding/json"
	"os/exec"
	"strings"
	"bufio"
)


// uploadWinToSiemAndRun: upload windows event logs to SIEM and Run Sigma rules to them
func uploadWinToSiemAndRun(w http.ResponseWriter, r *http.Request) {
	log.Println("Executed: uploadWinToSiemAndRun")

	switch r.Method {
		//POST takes the uploaded file(s) and saves it to disk.
		case "POST":
			//get the multipart reader for the request.
			reader, err := r.MultipartReader()

			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}

			//copy each part to destination.
			for {
				part, err := reader.NextPart()
				if err == io.EOF {
					break
				}

				// if part.FileName() is empty, skip this iteration.
				if part.FileName() == "" {
					continue
				}

				// if part.FileName() doesnt end with .evtx extension, show error
				fnameRegex := regexp.MustCompile(`.evtx$`)
				if !fnameRegex.Match([]byte(part.FileName())) {
					http.Error(w, "File must be a .evtx file", http.StatusInternalServerError)
					return
				}

				dst, err := os.Create("tmp/" + part.FileName())
				defer dst.Close()
				if err != nil {
					http.Error(w, err.Error(), http.StatusInternalServerError)
					return
				}
				
				if _, err := io.Copy(dst, part); err != nil {
					http.Error(w, err.Error(), http.StatusInternalServerError)
					return
				}

				// Log file uploaded info to logFileUploaded.csv
				tFormat := time.Now().Format("2006-01-02-15:04")
				data := []string{tFormat,part.FileName(),"Windows Event Log"}
				logFileToCsv(data)

				// Convert evtx format to []map[string]string of win events
				//res, fileHash := carveFileAndSendToGraylog(dst.Name(),0,0)

				// Send win events to SIEM
				if Siem == "graylog" {

					// sendLogsToGraylog(res)

					// Parse evtx and send concurrently to Graylog
					fileHash := carveFileAndSendToSiem(dst.Name(),0,0)

					// Run Sigma rules to logs uploaded
					
					// get sigma rules
					files, err := FilePathWalkDir(RulePath)
					if err != nil {
						log.Println("uploadWinToSiemAndRun: "+err.Error())
					}

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
								log.Println("uploadWinToSiemAndRun: "+err.Error())
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
								log.Println("uploadWinToSiemAndRun: "+err.Error())
							}

							// Run sigmac program to obtein siem query
							out, _ := exec.Command("sigmac", "-t", Siem, ruleFile).Output()
							//fmt.Printf("%s", out)
							query := string(out)

							// NOTE: There are rules that are not supported, skip them and log it. The query from rules unsupported are "" , but the sigmac output is "An unsupported feature is required for this Sigma rule: Aggregations not implemented for this backend Feel free to contribute for fun and fame, this is open source :) -> https://github.com/Neo23x0/sigma" 

							if query == "" {

								log.Println("uploadWinToSiemAndRun: Unsupported rule:  " + ruleFile)
						
								t := time.Now()
								tFormat := t.Format("2006-01-02-15:04")
								data := []string{tFormat,ruleFile,"Unsupported",config["title"],part.FileName()}
								infoAlerts = append(infoAlerts, data)

							// And if the rule is OK
							} else {

								queryLogs := strings.TrimSuffix(query, "\n") + " AND agentName:SigmaShooterAgent AND moduleName:UploadWindowsLogs AND logFileHash:"+fileHash
								byteValue, err:= runRuleQueryToGraylog(1, queryLogs)
								if err != nil {
									log.Println("uploadWinToSiemAndRun: "+err.Error())
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
									data := []string{tFormat,ruleFile,"0",config["title"],part.FileName()}
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
											log.Println("uploadWinToSiemAndRun: "+err.Error())
										}
									}

									// Log results 
									t := time.Now()
									tFormat := t.Format("2006-01-02-15:04")

									data := []string{tFormat,ruleFile,strconv.Itoa(count),config["title"],part.FileName()}
									infoAlerts = append(infoAlerts, data)
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

				} else if Siem == "X" {
					log.Println("In construction...")
					os.Exit(3)
				} else {
					log.Println("In construction...")
					os.Exit(3)
				}

				// Delete file
				//os.Remove("tmp/"+part.FileName())

			}
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
	}

	http.Redirect(w, r, "/logstosiem", http.StatusFound)
	return
}


// getLastFilesUploadedLogs: send last files logs uploaded
func getLastFilesUploadedLogs(w http.ResponseWriter, r *http.Request){

	// Create result variables
	type logsLastDay struct {
		Date 		string		`json:"date_log"`
		FileName 	string		`json:"fileName_log"`
	}
	var loglast logsLastDay
	var logs []logsLastDay

	// continue if executionsLog.csv exist
	if _, err := os.Stat("logFileUploaded.csv"); !os.IsNotExist(err) {
		// Open CSV
		csvFile, _ := os.Open("logFileUploaded.csv")
		reader := csv.NewReader(bufio.NewReader(csvFile))
		
		// Read CSV data
		var data [][]string
		data, err := reader.ReadAll()
		if err != nil {
			log.Println("getLastFilesUploadedLogs: "+err.Error())
		}
		
		today := time.Now()
		todayFormat := today.Format("2006-01-02")

		i := len(data)-1
		if strings.Contains(data[i][0],todayFormat) {

			for strings.Contains(data[i][0],todayFormat) {
				loglast.Date = data[i][0]
				loglast.FileName = data[i][1]
				logs = append(logs,loglast)
				i--
			}

		}
	} 

	if len(logs) == 0 {
		loglast.Date = "0"
		loglast.FileName = ""
		logs = append(logs,loglast)
	}

	// Send the result back to JS
	logsData := struct {
		Err   				int          	`json:"err"`
		FileLogs 			[]logsLastDay 	`json:"fileLogs"`
	}{
		0,
		logs,
	}

	ajaxResponse(w, logsData)
	return

}

// downloadFileUploadedLogs: serve logFileUploaded.csv
func downloadFileUploadedLogs(w http.ResponseWriter, r *http.Request){
	log.Println("Executed: downloadFileUploadedLogs")
	w.Header().Set("Content-Type", "application/csv")
	w.Header().Set("Content-Disposition", "attachment; filename=logFileUploaded.csv")
	http.ServeFile(w, r, "logFileUploaded.csv")
}