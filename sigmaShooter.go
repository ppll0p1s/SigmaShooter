package main

import (
	"log"
	"strconv"
	"strings"
	"bufio"
	"io"
	"os/exec"
	"os"

	"SigmaShooter/web"
)

const (
	version = "v0.01"
)

// Main function
func main() {

	// Init log headers
	log.SetPrefix("[●] ")
	log.SetFlags(log.Ldate | log.Ltime | log.Lmicroseconds)

	// Read config file
	config, err := ReadConfig(`sigmaShooter.conf`)
	if err != nil {
 		log.Println(err)
 	}

 	// Write log file
 	logDir := config["logDir"]
 	f, err := os.OpenFile(logDir, os.O_RDWR | os.O_CREATE | os.O_APPEND, 0666)
	if err != nil {
	    log.Println("main: error opening log path or file: " + err.Error())
	}
	defer f.Close()
	log.SetOutput(f)
	log.Printf("Starting SigmaShooter server %s", version)

	// Check requirements
	check := checkRequirements(config)
	if check != ""{
	    log.Fatal("main: checking reqs... FAIL.\nCheck requirements to run the app. \nChecks: " + check)
	} 

 	// Set variables from config
 	addr := config["addr"]
 	port := config["port"]

	// Set variables for web handler
	web.RulePath 	= config["rulePath"]
	web.RuleBakPath = config["ruleBakPath"]

	if config["siem"] == "graylog" {
		web.Version 		= version
		web.Siem 			= config["siem"]
		web.SiemAddr 		= config["siemAddr"]
		web.SiemPortApi 	= config["siemPortApi"]
		web.SiemUrlApi 		= config["siemUrlApi"]
		web.SiemToken 		= config["siemToken"]

		siemPortInputu64, err := strconv.ParseUint(config["siemPortInput"], 10, 64)
		if err != nil {
			log.Println("main - SiemPortInput "+err.Error())
		}
		web.SiemPortInput 	= uint(siemPortInputu64)

	} else if config["siem"] == "X" {
		log.Println("In construction...")
		os.Exit(3)
	} else {
		log.Println("In construction...")
		os.Exit(3)
	}

	// Start Web router goroutine
	web.Router(addr, port)
}


// ====================
// = Helper functions =
// ====================

// ReadConfig: read variables from sigmaShooter.conf file
type Config map[string]string
func ReadConfig(filename string) (Config, error) {
    // init with some bogus data
	config := Config{
		"addr":					"",
		"port":           		"",
		"siem":          		"",
		"siemAddr":      		"",
		"siemPortApi":      	"",
		"siemUrlApi":      		"",
		"siemPortInput":      	"",
		"siemToken":      		"",
		"rulePath":      		"",
		"ruleBakPath":      	"",
		"logDir":      			"",
	}
	if len(filename) == 0 {
		return config, nil
	}
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	
	reader := bufio.NewReader(file)
	
	for {
		line, err := reader.ReadString('\n')
		
		// check if the line has = sign
        // and process the line. Ignore the rest.
		if equal := strings.Index(line, "="); equal >= 0 {
			if key := strings.TrimSpace(line[:equal]); len(key) > 0 {
				value := ""
				if len(line) > equal {
					value = strings.TrimSpace(line[equal+1:])
				}
                // assign the config map
				config[key] = value
			}
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
	}
	return config, nil
}

// checkRequirements: check requirements to run the app correctly
func checkRequirements(config Config) (string) {
	log.Println("checkRequirements: checking reqs...")

	check := ""

	// Check requirements.txt
	// NOTE: Check commands will return errors, but we assume them to check if the command is in the system or not.
	// sigmac command
	_, err := exec.Command("sigmac").Output()
	if err != nil {
		if strings.Contains(err.Error(), "executable file not found") {
			check = check + "ERROR: sigmac not found.\n"
		} 
	}
	

	// Check config vars
	if config["addr"] == "" {
		check = check + "ERROR: addr empty value.\n"
	} else if config["port"] == "" {
		check = check + "ERROR: port empty value.\n"
	} else if config["siem"] == "" {
		check = check + "ERROR: siem empty value.\n"
	} else if config["siemAddr"] == "" {
		check = check + "ERROR: siemAddr empty value.\n"
	} else if config["siemPortApi"] == "" {
		check = check + "ERROR: siemPortApi empty value.\n"
	} else if config["siemUrlApi"] == "" {
		check = check + "ERROR: siemUrlApi empty value.\n"
	} else if config["siemPortInput"] == "" {
		check = check + "ERROR: siemPortInput empty value.\n"
	} else if config["siemToken"] == "" {
		check = check + "ERROR: siemToken empty value.\n"
	} else if config["rulePath"] == "" {
		check = check + "ERROR: rulePath empty value.\n"
	} else if config["ruleBakPath"] == "" {
		check = check + "ERROR: ruleBakPath empty value.\n"
	} //else if config["logDir"] == "" {
		//check = check + "ERROR: logDir empty value.\n"
	//}

	// Check paths
	// tmp/ path for tmp files used by the app (p.e. content rule)
	if _, err := os.Stat("tmp/"); os.IsNotExist(err) {
		if err := os.MkdirAll("tmp/", 0755); err != nil {
			log.Println("checkRequirements: "+err.Error())
		} else {
			log.Println("checkRequirements: INFO: tmp/ path created for SigmaShooter App.")
		}
	}
	// rulePath/
	if _, err := os.Stat(config["rulePath"]); os.IsNotExist(err) {
		check = check + "ERROR: rulePath value does not exist. Create it to continue.\n"
	}
	// ruleBakPath/
	if _, err := os.Stat(config["ruleBakPath"]); os.IsNotExist(err) {
		check = check + "ERROR: ruleBakPath value does not exist. Create it to continue.\n"
	}
	// logDir/
	//if _, err := os.Stat(config["logDir"]); os.IsNotExist(err) {
		//check = "ERROR: logDir value does not exist. Create it to continue.\n"
	//}

	if check == "" {
		log.Println("checkRequirements: checking reqs... OK")
	}
	return check
}
