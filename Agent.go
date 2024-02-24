package main

import (
	"github.com/TwiN/go-color"
	"fmt"
	"net"
	"os"
	"bufio"
	"flag"
	"debug/pe"
	"time"
	"strconv"
	"crypto/md5"
	"io"
	"encoding/hex"
	"strings"
	"regexp"
	"math"
	//"sort"
	//"net/http"
)

var (
	backdoor = color.Ize(color.Red, "[BKDR]")
	upload = color.Ize(color.Blue, "[UPLD]")
	api = color.Ize(color.Purple, "[APIU]")
	github = color.Ize(color.Green, "[GITH]")
	paste = color.Ize(color.Red, "[PSTE]")
	executeable = color.Ize(color.Red, "[EXEC]")
	interesting_links = color.Ize(color.Bold, "Intersting Links [")
	info = color.Ize(color.Blue, "[INFO]")
	intest = color.Ize(color.Green, "[INTS]")
	file_type = color.Ize(color.Green, "[ARCH]")
	file_hash = color.Ize(color.Cyan, "[File HASH]")
	total_url = color.Ize(color.Green, "[Total URL Found]")
	md5hash = color.Ize(color.Purple, "[MD5]")
	detection_rate = color.Ize(color.Red, "[DETR]")
	fileformat = color.Ize(color.Green, "[File Format]")
	Module = color.Ize(color.Blue, "[MODL]")
	unknown = color.Ize(color.Green, "[UNKN]")
	functions_found = color.Ize(color.Bold, "Functions Found [")
	NumberOfSections = color.Ize(color.Purple, "[Number of Sections]")
	SizeOfOptionalHeader = color.Ize(color.Red, "[Size of Optional Header]")
	bannerdown = color.Ize(color.Purple, "[Bin-Analyzer v1.0 (Golang Binary Analyzer)]")
	fileinformation = color.Ize(color.Bold, "File Information [")
	backdoors = color.Ize(color.Bold, "Possible Backdoor Found [")
	antivirus_scan = color.Ize(color.Bold, "Cymru Malware Database Match [")
	lastbrace = color.Ize(color.Bold, "]")
	cymru = color.Ize(color.Green, "[Cymru Malware Detection]")
	total_url_found = color.Ize(color.Green, "[Total URL Found]")
	pastesin = color.Ize(color.Bold, "Pastes links found [")
	function_i = color.Ize(color.Yellow, "[GoFunction]")
	devloped = color.Ize(color.White, "[Devloped by: armx64 ]")
	expired = color.Ize(color.Red, "[Expired]")
	licensed = color.Ize(color.Green, "[Community License]")
)
func check_connectivity() string{
	_, err := net.Dial("tcp", "google.com:80")
	if err != nil {
		return color.Ize(color.Red,"[Disconnected]")
	} else {
		return color.Ize(color.Green,"[Connected]")
	}
}

func binreader(filename string) (output []string, err error) {
    file, err := os.Open(filename)
    if err != nil {
        return nil, err
    }
    defer file.Close()

    scanner := bufio.NewScanner(file)
    scanner.Split(bufio.ScanBytes)

    var text []byte
    for scanner.Scan() {
        b := scanner.Bytes()[0]
        if b >= 32 && b <= 126 {
            text = append(text, b)
        } else {
            if len(text) >= 4 {
                output = append(output, string(text))
            }
            text = text[:0]
        }
    }
    if len(text) >= 4 {
        output = append(output, string(text))
    }

    return output, nil
}


type Information struct {
	FileType              string
	NumberOfSections      int
	TimeDateStamp         string
	PointerToSymbolTable  uint32
	NumberOfSymbols       uint32
	SizeOfOptionalHeader  uint16
	Characteristics       uint16
	Sections              []SectionInformation
}

type SectionInformation struct {
	Name           string
	VirtualSize    uint32
	VirtualAddress uint32
	Size           uint32
	Offset         uint32
	Reloc          uint32
	Line           uint32
	Characteristics uint32
}

func binInfo(fileName string) (Information, error) {
	var info Information

	file, err := pe.Open(fileName)
	if err != nil {
		return info, err
	}
	defer file.Close()

	switch file.FileHeader.Machine {
	case 0x14c:
		info.FileType = "Intel 386"
	case 0x8664:
		info.FileType = "AMD64"
	default:
		info.FileType = "Unknown"
	}

	info.NumberOfSections = len(file.Sections)
	info.TimeDateStamp = time.Unix(int64(file.FileHeader.TimeDateStamp), 0).String()
	info.PointerToSymbolTable = file.FileHeader.PointerToSymbolTable
	info.NumberOfSymbols = file.FileHeader.NumberOfSymbols
	info.SizeOfOptionalHeader = file.FileHeader.SizeOfOptionalHeader
	info.Characteristics = file.FileHeader.Characteristics

	return info, nil
}
func fileHash(filePath string) ([]byte, error) {
	f, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	h := md5.New()
	if _, err := io.Copy(h, f); err != nil {
		return nil, err
	}

	return h.Sum(nil), nil
}
func MalwareLookup(hash string) (string, error) {
	domain := fmt.Sprintf("%s.hash.cymru.com", hash)

	txts, err := net.LookupTXT(domain)
	if err != nil {
		return "", err
	}

	split := strings.Split(txts[0], " ")
	return split[1], nil
}
func extractUrl(text string) (url string) {
    re := regexp.MustCompile(`(http|https):\/\/([\w\-_]+(?:(?:\.[\w\-_]+)+))([\w\-\.,@?^=%&amp;:/~\+#]*[\w\-\@?^=%&amp;/~\+#])?`)
    matches := re.FindStringSubmatch(text)
    if len(matches) > 0 {
        url = matches[0]
    }
    return url
}
func pastecheck(url string) string {
	if strings.Contains(url, "pastebin.com") ||
		strings.Contains(url, "gist.github.com") ||
		strings.Contains(url, "hastebin.com") ||
		strings.Contains(url, "paste.ubuntu.com") ||
		strings.Contains(url, "gist.githubusercontent.com") ||
		strings.Contains(url, "pastie.org") ||
		strings.Contains(url, "paste.debian.net") ||
		strings.Contains(url, "paste.org.ru") ||
		strings.Contains(url, "paste2.org") ||
		strings.Contains(url, "paste.ee") ||
		strings.Contains(url, "paste.firefox.com") ||
		strings.Contains(url, "paste.lisp.org") ||
		strings.Contains(url, "paste.pound-python.org") ||
		strings.Contains(url, "paste.xinu.at") ||
		strings.Contains(url, "paste2.org") ||
		strings.Contains(url, "paste.debian.net") ||
		strings.Contains(url, "apaste.info") ||
		strings.Contains(url, "bitbin.it") ||
		strings.Contains(url, "quickhighlighter.com") ||
		strings.Contains(url, "pastesite.com") ||
		strings.Contains(url, "slexy.org") ||
		strings.Contains(url, "dpaste.com") ||
		strings.Contains(url, "codepaste.net") ||
		strings.Contains(url, "pastebay.net") {
		return paste+" "+url
	}
	return ""
}

func interestingLinks(url string) string {
	keywords := []string{"api", "upload", "post", "download", "data", "information", "resources"}

	for _, keyword := range keywords {
		if strings.Contains(url, keyword) {
			return intest+" "+url
		}
	}
	return ""
}



func checkForBackdoor(url string)  string{
	if strings.Contains(url, "telegram") ||
		strings.Contains(url, "api.icq.net") ||
		strings.Contains(url, "discord") ||
		strings.Contains(url, "discordapp.com") ||
		strings.Contains(url, "graph.facebook.com") ||
		strings.Contains(url, "slack.com/") ||
		strings.Contains(url, "discord.com") {
		fmt.Println(backdoor, url)
	}
	return ""
}




func licenseinfo() {
	expiry_date := "2024-12-21"
	if time.Now().After(time.Date(2024, 12, 21, 0, 0, 0, 0, time.UTC)) {
		fmt.Println("        "+expired)
		os.Exit(1)

	} else {
		today := time.Now()
		expiry, _ := time.Parse("2006-01-02", expiry_date)
		days_left := expiry.Sub(today).Hours() / 24
		days_left = math.Round(days_left)
		fmt.Println("        "+licensed, "Days left:", days_left,"\n")
	}
}

func logo(){
	connection := check_connectivity()
	fmt.Println(`
	 ___ _           _                 
	| _ |_)_ _  __ _| |_  _ ______ _ _ 
	| _ \ | ' \/ _  | | || |_ / -_) '_|
	|___/_|_||_\__,_|_|\_, /__\___|_|  
			   |__/  `+connection+`
	`+bannerdown+`
	`+devloped+``)
}

func main() {
	logo()
	licenseinfo()
	var file string
	flag.StringVar(&file, "bin", "", "File to analyze")
	flag.Parse()
	if file == "" {
		fmt.Println(info, "Please specify a file to analyze")
		fmt.Println(info, "Usage: binalyzer -bin <file>")
	}
	_, err := os.Stat(file)
	if err != nil {
		fmt.Println(info, "File does not exist")
	}
	fmt.Println(executeable, file)
	fmt.Println("--")
	info, err := binInfo(file)
	if err != nil {
		panic(err)
	}
	filehashi, err := fileHash(file)
	if err != nil {
		panic(err)
	}
	filehash := hex.EncodeToString(filehashi)
	fmt.Println(fileinformation+`
	`+file_type+` - `+info.FileType+`
	`+NumberOfSections+` - `+strconv.Itoa(info.NumberOfSections)+`
	`+SizeOfOptionalHeader+` - `+strconv.Itoa(int(info.SizeOfOptionalHeader))+`
	`+file_hash+` - `+filehash+`
`+lastbrace)
	fmt.Println("--")
	malware, err := MalwareLookup(filehash)
	if err != nil {
		malware = "0%"
	}
	fmt.Println(antivirus_scan+`
	`+cymru+` - `+malware+`
`+lastbrace)
	fmt.Println("--")
	output, err := binreader(file)
	if err != nil {
		fmt.Println("X_X")
	}
	var urls []string
	var buildid []string
	var functions []string
	for _, line := range output {
		url := extractUrl(line)
		if url != "" {
			urls = append(urls, url)
		}
		build := GoBuildID(line)
		functionname := regexp.MustCompile(`main(.*).func`)
		match := functionname.FindStringSubmatch(line)
		if len(match) > 1 {
			if len(match[1]) < 20 {
				if match[1] != "" {
					fucntions := match[1][1:]
					functions = append(functions, fucntions)
				}
			}
		}
	}
	fmt.Println(total_url_found, len(urls))
	fmt.Println("--")
	fmt.Println(backdoors+``)
	for _, url := range urls {
		backd := checkForBackdoor(url)
		if backd != "" {
			fmt.Println(`		`+backd+`

		`)
		}
	
	}
	fmt.Println(lastbrace)
	fmt.Println("--")
	fmt.Println(pastesin+``)
	for _, url := range urls {
		paste := pastecheck(url)
		if paste != "" {
			fmt.Println(``+paste+``)
		}
	}
	fmt.Println(lastbrace)
	
	fmt.Println("--")
	fmt.Println(interesting_links+``)
	for _, url := range urls {
		interesting := interestingLinks(url)
		if interesting != "" {
			fmt.Println(``+interesting+``)
		}
	}
	fmt.Println(lastbrace)
	fmt.Println("--")
	fmt.Println(``+functions_found+``)
	unique := make(map[string]bool)
	for _, item := range functions {
		unique[item] = true
	}
	for key := range unique {
		fmt.Println(``+function_i+` `+key+`()`)
	}
	fmt.Println(lastbrace)





	

}
