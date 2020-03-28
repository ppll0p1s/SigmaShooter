package web

import (
	"fmt"
	"net/http"
	"regexp"
	"os"
	"path/filepath"
	"log"
	"strings"
	"encoding/json"
	"encoding/csv"
	"bufio"
	"io/ioutil"
	"io"
	"net/url"
	"strconv"
	"time"
	"crypto/md5"
	"encoding/hex"
	"bytes"
	"archive/tar"
	"compress/gzip"
	"errors"

	"github.com/Devatoria/go-graylog"
	"github.com/0xrawsec/golang-evtx/evtx"
	//"github.com/0xrawsec/golang-utils/log"
	"github.com/jeremywohl/flatten"
)

// ====================
// = Helper functions =
// ====================

// ajaxResponse: send json response data to JS
func ajaxResponse(rw http.ResponseWriter, data interface{}) {
	// AJAX Response
	rw.Header().Set("Content-Type", "application/json; charset=UTF-8")
	rw.WriteHeader(http.StatusCreated)

	if err := json.NewEncoder(rw).Encode(data); err != nil {
		sendJSONError(rw, http.StatusInternalServerError, err)
		return
	}
}

// sendJSONError: send json error if ajaxResponse func fails
func sendJSONError(rw http.ResponseWriter, code int, err error) {
	rw.Header().Set("Content-Type", "application/json; charset=UTF-8")
	rw.WriteHeader(code)
	if err := json.NewEncoder(rw).Encode(err); err != nil {
		log.Println("sendJSONError: "+err.Error())
	}
}

// targzit: targzit a path
func targzit(source, target, targzName string) error {
	//filename := filepath.Base(source)

	// TAR
	target = filepath.Join(target, fmt.Sprintf("%s.tar", targzName))
	tarfile, err := os.Create(target)
	if err != nil {
		return err
	}
	defer tarfile.Close()

	tarball := tar.NewWriter(tarfile)
	defer tarball.Close()

	info, err := os.Stat(source)
	if err != nil {
		return nil
	}

	var baseDir string
	if info.IsDir() {
		baseDir = filepath.Base(source)
	}

	err = filepath.Walk(source, 
	func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		header, err := tar.FileInfoHeader(info, info.Name())
		if err != nil {
			return err
		}

		if baseDir != "" {
			header.Name = filepath.Join(baseDir, strings.TrimPrefix(path, source))
		}

		if err := tarball.WriteHeader(header); err != nil {
			return err
		}

		if info.IsDir() {
			return nil
		}

		file, err := os.Open(path)
		if err != nil {
			return err
		}
		defer file.Close()
		_, err = io.Copy(tarball, file)
		return err

	})
	if err != nil {
		return err
	}
	// END TAR

	// GZIP
	err = gzipit(target,RuleBakPath)
	if err != nil {
		return err
	}
	// END GZIP

	// Remove tar
	err = os.Remove(target)
	if err != nil {
		return err
	}

	return nil

}

// untargzit: untar a tar.gz into a path
func untargzit(targz, target string) error {
	// UNGZIP
	filename, err := ungzip(targz,"tmp/")
	if err != nil {
		return err
	}
	// END UNGZIP

	// UNTAR
	reader, err := os.Open("tmp/"+filename)
	if err != nil {
		return err
	}
	defer reader.Close()
	tarReader := tar.NewReader(reader)

	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			break
		} else if err != nil {
			return err
		}

		path := filepath.Join(target, header.Name)
		info := header.FileInfo()
		if info.IsDir() {
			if err = os.MkdirAll(path, info.Mode()); err != nil {
				return err
			}
			continue
		}

		file, err:= os.OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, info.Mode())
		if err != nil {
			if strings.Contains(err.Error(),"no such file or directory") {
				rest := strings.Split(path,"/")
				// Get permissions
				perm, err := os.Stat(rest[0])
				resDir := strings.TrimRight(path,rest[len(rest)-1])
				if err = os.MkdirAll(resDir, perm.Mode()); err != nil {
					return err
				}
				continue
			}
			return err
		}
		defer file.Close()
		_, err =io.Copy(file, tarReader)
		if err != nil {
			return err
		}
	}
	// END UNTAR

	// Remove tar
	err = os.Remove("tmp/"+filename)
	if err != nil {
		return err
	}

	return nil
}

// gzipit: gzip source
func gzipit(source, target string) error {
	reader, err := os.Open(source)
	if err != nil {
		return err
	}

	filename := filepath.Base(source)
	target = filepath.Join(target, fmt.Sprintf("%s.gz", filename))
	writer, err := os.Create(target)
	if err != nil {
		return err
	}
	defer writer.Close()

	archiver := gzip.NewWriter(writer)
	archiver.Name = filename
	defer archiver.Close()

	_, err = io.Copy(archiver, reader)
	return err
}

// ungzip: ungzip source
func ungzip(source, target string) (string, error) {
	filename := strings.TrimRight(source,".gz")

	reader, err := os.Open(source)
	if err != nil {
		return filename, err
	}
	defer reader.Close()

	archive, err := gzip.NewReader(reader)
	if err != nil {
		return filename, err
	}
	defer archive.Close()

	target = filepath.Join(target, filename)
	writer, err := os.Create(target)
	if err != nil {
		return filename, err
	}
	defer writer.Close()

	_, err = io.Copy(writer, archive)
	if err != nil {
		return filename, err
	}

	return filename, err
}

// getPathRuleNameById: return rule name and path from a given node id
func getPathRuleNameById(ruleId string) (string, string) {
	resRuleName := ""
	resRulePath := ""

	file, err := os.Open("rules.db")
    if err != nil {
        log.Fatal(err)
    }
    defer file.Close()

    scanner := bufio.NewScanner(file)
    for scanner.Scan() {
    	line := strings.Split(scanner.Text(),",")

        if line[0] == ruleId {
        	resRuleName = line[1]
        	resRulePath = line[2]
        	break
        }
    }

    if err := scanner.Err(); err != nil {
        log.Fatal(err)
    }

    return resRuleName, resRulePath

}

// checkNameTarFile: check values entered by the user to avoid attacks
func checkNameTarFile(val string) (bool) {
	sanit, _ := regexp.MatchString("^[a-zA-Z0-9_-]*.tar.gz$", val)
	return sanit
}

// checkNameFolder: check values entered by the user to avoid attacks
func checkNameFolder(val string) (bool) {
	sanit, _ := regexp.MatchString("^[a-zA-Z0-9_ -]*$", val)
	return sanit
}

// checkNamePath: check values entered by the user to avoid attacks
func checkNamePath(val string) (bool) {
	sanit, _ := regexp.MatchString("^[a-zA-Z0-9_ -\\/]*$", val)
	return sanit
}

// checkNamePathRule: check values entered by the user to avoid attacks
func checkNamePathRule(val string) (bool) {
	sanit, _ := regexp.MatchString("^[a-zA-Z0-9_ -\\/]*.yml$", val)
	return sanit
}

// FilePathWalkDir: return path walk and error from a given path
func FilePathWalkDir(ruthPath string) ([]string, error) {
	var files []string
	err := filepath.Walk(ruthPath, func(path string, info os.FileInfo, err error) error {
		if !info.IsDir() {
			files = append(files, path)
		}
		return nil
		})
	return files, err
}

// getSigmaRuleInfo: get Sigma rule content info
type Config map[string]string
func getSigmaRuleInfo(ruleFile string) (Config, error) {

	// Select fields wanted from sigma rule
	config := Config{
		"title":  "",
		"level":  "",
	}

	file, err := os.Open(ruleFile)
	if err != nil {
		log.Println("getSigmaRuleInfo: "+err.Error())
	}
	defer file.Close()

	reader := bufio.NewReader(file)

	// Get values selected in Config map
	for {
		line, err := reader.ReadString('\n')

     	// check if the line has : sign and process it. Ignore the rest.
		if equal := strings.Index(line, ":"); equal >= 0 {
			if key := strings.TrimSpace(line[:equal]); len(key) > 0 {
				value := ""
				if len(line) > equal {
					value = strings.TrimSpace(line[equal+1:])
				}
                // assign map
				config[key] = value
			}
		}	
		if err == io.EOF {
			break
		}
		if err != nil {
			log.Println("getSigmaRuleInfo: "+err.Error())
		}
	}

	return config, err

}

// hash_file_md5: return hash of a file
func hash_file_md5(filePath string) (string, error) {
	//Initialize variable returnMD5String now in case an error has to be returned
	var returnMD5String string

	//Open the passed argument and check for any error
	file, err := os.Open(filePath)
	if err != nil {
		return returnMD5String, err
	}

	//Tell the program to call the following function when the current function returns
	defer file.Close()

	//Open a new hash interface to write to
	hash := md5.New()

	//Copy the file in the hash interface and check for any error
	if _, err := io.Copy(hash, file); err != nil {
		return returnMD5String, err
	}

	//Get the 16 bytes hash
	hashInBytes := hash.Sum(nil)[:16]

	//Convert the bytes to a string
	returnMD5String = hex.EncodeToString(hashInBytes)

	return returnMD5String, nil
}

// Convert evtx format to json helpers

var (
	chunkHeaderRE = regexp.MustCompile(evtx.ChunkMagic)
	defaultTime   = time.Time{}
)

// findChunksOffsets: Find the potential chunks
func findChunksOffsets(r io.ReadSeeker) (co chan int64) {
	co = make(chan int64, 42)
	realPrevOffset, _ := r.Seek(0, os.SEEK_CUR)
	go func() {
		defer close(co)
		rr := bufio.NewReader(r)
		for loc := chunkHeaderRE.FindReaderIndex(rr); loc != nil; loc = chunkHeaderRE.FindReaderIndex(rr) {
			realOffset, _ := r.Seek(0, os.SEEK_CUR)
			co <- realPrevOffset + int64(loc[0])
			realPrevOffset = realOffset - int64(rr.Buffered())
		}
	}()
	return
}

// carveFileAndSendToSiem: main routine to carve a file and send to SIEM
func carveFileAndSendToSiem(datafile string, offset int64, limit int) (string){

	//var res []map[string]string
	var logFileName, logFileHash string

	chunkCnt := 0
	f, err := os.Open(datafile)
	if err != nil {
		log.Println("carveFileAndSendToSiem: "+err.Error())
	}
	// Set file vars
	logFileName = strings.Trim(f.Name(),"tmp/")
	logFileHash, err = hash_file_md5(datafile)
	if err != nil {
		log.Println("carveFileAndSendToSiem: hash_file_md5: "+err.Error())
	}

	defer f.Close()
	f.Seek(offset, os.SEEK_SET)

	dup, err := os.Open(datafile)
	if err != nil {
		log.Println("carveFileAndSendToSiem: "+err.Error())
	}
	defer dup.Close()
	dup.Seek(offset, os.SEEK_SET)

	// Open a 
	g, err := graylog.NewGraylog(graylog.Endpoint {
		Transport: graylog.TCP,
		Address:   SiemAddr,
		Port:      SiemPortInput,
	})
	if err != nil {
		log.Println("carveFileAndSendToSiem: "+err.Error())
	}

	if Siem == "graylog" {
		for offset := range findChunksOffsets(f) {
			//log.Infof("Parsing Chunk @ Offset: %d (0x%08[1]x)", offset)
			chunk, err := fetchChunkFromReader(dup, offset)
			if err != nil {
				log.Println("carveFileAndSendToSiem: "+err.Error())
			}
			for e := range chunk.Events() {
				r := printEvent(e,logFileName,logFileHash)
				//res = append(res,r)
				go sendLogsToGraylog(r,g)
			}
			chunkCnt++

			if limit > 0 && chunkCnt >= limit {
				break
			}
			//log.Debug("End of the loop")
		}
	} else if Siem == "X" {
		log.Println("In construction...")
		os.Exit(3)
	} else {
		log.Println("In construction...")
		os.Exit(3)
	}

	//return res, logFileHash
	return logFileHash
}

// fetchChunkFromReader: return an evtx.Chunk object from a reader
func fetchChunkFromReader(r io.ReadSeeker, offset int64) (evtx.Chunk, error) {
	var err error
	c := evtx.NewChunk()
	evtx.GoToSeeker(r, offset)
	c.Offset = offset
	c.Data = make([]byte, evtx.ChunkSize)
	if _, err = r.Read(c.Data); err != nil {
		return c, err
	}
	reader := bytes.NewReader(c.Data)
	c.ParseChunkHeader(reader)
	if err = c.Header.Validate(); err != nil {
		return c, err
	}
	// Go to after Header
	evtx.GoToSeeker(reader, int64(c.Header.SizeHeader))
	c.ParseStringTable(reader)
	err = c.ParseTemplateTable(reader)
	if err != nil {
		return c, err
	}
	err = c.ParseEventOffsets(reader)
	if err != nil {
		return c, err
	}
	return c, nil
}

// printEvent: small routine that return the post content of the windows event
func printEvent(e *evtx.GoEvtxMap, logFileName, logFileHash string) map[string]string{
	
	var resTemp map[string]string
	res := make(map[string]string)

	if e != nil {

		flat, _ := flatten.FlattenString(string(evtx.ToJSON(e)), "", flatten.DotStyle)

		err := json.Unmarshal([]byte(flat), &resTemp)
		if err!=nil {
			log.Println("printEvent: "+err.Error())
		}

		for key, value := range resTemp {
			newKey := strings.Split(key,".")
			newKey2 := newKey[len(newKey)-1]

			res[newKey2] = value

            //fmt.Printf("%s -> %s\n", newKey2, value)
        }

        // Add SigmaShooter module info
        res["agentName"] = "SigmaShooterAgent"
		res["moduleName"] = "UploadWindowsLogs"
		res["logFileName"] = logFileName
		res["logFileHash"] = logFileHash
	}
	return res
}

// logFileToCsv: log file uploaded info to logFileUploaded.csv
func logFileToCsv(data []string) {
	var infoFile [][]string
	
	if _, err := os.Stat("logFileUploaded.csv"); os.IsNotExist(err) {
		logFileCsv, err := os.Create("logFileUploaded.csv")
		if err != nil {
			log.Println("logFileToCsv: "+err.Error())
		}

		columns := []string{"Date","Log File Name","Type"}
		infoFile = append(infoFile, columns)
		infoFile = append(infoFile, data)

		csvWriter := csv.NewWriter(logFileCsv)
		csvWriter.WriteAll(infoFile)
		csvWriter.Flush()
		defer logFileCsv.Close()

	} else {
		logFileCsv, _ := os.OpenFile("logFileUploaded.csv", os.O_WRONLY|os.O_APPEND, 0644)
		csvWriter := csv.NewWriter(logFileCsv)
		infoFile = append(infoFile, data)
		csvWriter.WriteAll(infoFile)
		csvWriter.Flush()
		defer logFileCsv.Close()
	}
}

// RemoveContents: remove contents from a dir, but not the dir
func RemoveContents(dir string) error {
    files, err := filepath.Glob(filepath.Join(dir, "*"))
    if err != nil {
        return err
    }
    for _, file := range files {
        err = os.RemoveAll(file)
        if err != nil {
            return err
        }
    }
    return nil
}

// ==========================
// Graylog SIEM helpers
// ==========================

// checkConnGraylog: check connectivity to Graylog
func checkConnGraylog() error {

	// Adjust Graylog SIEM server parameters
	graylogAddr := "http://"+SiemAddr+":"+SiemPortApi
	apiUrlPath := SiemUrlApi+"cluster"
	token := SiemToken

	// Encode the query to url encoding
	var Url *url.URL
	Url, err := url.Parse(graylogAddr)
	if err != nil {
		log.Println("checkConnGraylog: "+err.Error())
	}
	Url.Path += apiUrlPath
	q := Url.String()

	// Send query to graylog
	var client http.Client
	req, err := http.NewRequest("GET", q, nil)
	req.SetBasicAuth(token, "token")
	resp, err := client.Do(req)
	if err != nil{
		log.Println("checkConnGraylog: "+err.Error())
	}
	
	if resp.StatusCode == 200 {
		return nil
	}

	err = errors.New("Connection failed.")
	return err
}

// runRuleQueryToGraylog: search sigma rule query to Graylog
func runRuleQueryToGraylog(days int, query string) ([]byte, error) {

	// Adjust Graylog SIEM server parameters
	graylogAddr := "http://"+SiemAddr+":"+SiemPortApi
	apiUrlPath := SiemUrlApi+"search/universal/relative"
	token := SiemToken

	// Encode the query to url encoding
	var Url *url.URL
	Url, err := url.Parse(graylogAddr)
	if err != nil {
		log.Println("runRuleQueryToGraylog: "+err.Error())
	}

	// Set time relative to search in graylog
	var timeRelative int
	if days == 1 {
		timeRelative = days*86400
	} else if days == 5 {
		timeRelative = days*86400
	} else if days == 14 {
		timeRelative = days*86400
	}

	Url.Path += apiUrlPath
	parameters := url.Values{}
	parameters.Add("query", query)
	parameters.Add("range", strconv.Itoa(timeRelative))
	parameters.Add("decorate", "true")
	Url.RawQuery = parameters.Encode()
	
	//fmt.Printf("Encoded URL is %q\n", Url.String())

	q := Url.String()
	// Values.Encode() encode spaces with +. This cause problems to Graylog queries. Changing + to %20
	q = strings.ReplaceAll(q,"+","%20")

	// Send query to graylog
	var client http.Client
	req, err := http.NewRequest("GET", q, nil)
	req.SetBasicAuth(token, "token")
	resp, err := client.Do(req)
	if err != nil{
		log.Println("runRuleQueryToGraylog: "+err.Error())
	}
	byteValue, err := ioutil.ReadAll(resp.Body)
	
	//s := string(bodyText)
	//fmt.Print(s)

	return byteValue, err
}

//sendAlertsToGraylog:
func sendAlertsToGraylog(ruleFile string, config Config, message map[string]interface{}) error {
	mapString := make(map[string]string)
	fullMessage := "Sigma rule title: "+config["title"]+" # Sigma rule level: "+config["level"]

	// Example of key/value:
	// key = Image
	// value = C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
	for key, value :=range message {
		strKey := fmt.Sprintf("%v", key)
		strValue := fmt.Sprintf("%v", value)
		mapString[strKey] = strValue
		fullMessage = fullMessage+" # "+strKey+": "+strValue
	}

	// Complete mapString var which will be send to SIEM
	mapString["SigmaRuleFile"] = ruleFile
	mapString["SigmaRuleTitle"] = config["title"]
	mapString["SigmaRuleLevel"] = config["level"]
	mapString["agentName"] = "SigmaShooterAgent"
	mapString["moduleName"] = "Alerts"

	// Send alerts to graylog via GELF
	// TODO: Initialize a new graylog client with TLS

	g, err := graylog.NewGraylog(graylog.Endpoint {
		Transport: graylog.TCP,
		Address:   SiemAddr,
		Port:      SiemPortInput,
	})
	if err != nil {
		log.Println("sendAlertsToGraylog: "+err.Error())
	}

	// Send alert
	err = g.Send(graylog.Message{
		Version:      	"1.1",
		Host:         	"SigmaShooter Server",
		ShortMessage: 	"SigmaShooter: Alert("+config["level"]+") - "+config["title"],
		FullMessage:  	fullMessage,
		Timestamp:    	time.Now().Unix(),
		Level:        	1, 
		Extra:			mapString,
	})

	if err != nil {
		log.Println("sendAlertsToGraylog: "+err.Error())
	}
	
	// Close the graylog connection
	if err := g.Close(); err != nil {
		log.Println("sendAlertsToGraylog: "+err.Error())
	}

	return err
}

// sendLogsToGraylog: send logs to Graylog
func sendLogsToGraylog(r map[string]string, g *graylog.Graylog) {

	var fullMessage string
	for key, value :=range r {
		fullMessage = fullMessage+" # "+key+": "+value
	}

	// Send log
	err := g.Send(graylog.Message{
		Version:      	"1.1",
		Host:         	"SigmaShooter Server",
		ShortMessage:   "Log uploaded from file: "+r["logFileName"],
		FullMessage:    fullMessage,
		Timestamp:    	time.Now().Unix(),
		Level:        	1, 
		Extra:			r,
	})
	if err!=nil {
		log.Println("sendLogsToGraylog: "+err.Error())
	}

}

// ==========================
// End Graylog SIEM helpers
// ==========================

// ==========================
// Other SIEM helpers
// ==========================

// In construction...

// ==========================
// End Graylog SIEM helpers
// ==========================