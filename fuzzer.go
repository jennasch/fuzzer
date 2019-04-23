package notionFuzz

import (
	"encoding/binary"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/notion/bastion/asciicast"
	"github.com/notion/bastion/config"
	"github.com/notion/bastion/web"
)

var (
	monAddr      = flag.String("mon.addr", ":9501", "The address to listen for prom connections on")
	webAddr      = flag.String("web.addr", ":8080", "The address to listen for http connections on")
	sshAddr      = flag.String("ssh.addr", ":5222", "The address to listen for ssh connections on")
	sshProxyAddr = flag.String("ssh.proxy.addr", "localhost:22222", "The address to listen for ssh proxy connections on")
	forceCerts   = flag.Bool("ssh.force-certs", false, "Force certificate generation")
)

func Fuzz(data []byte) int {
	// each of the following three functions fuzzes different areas of the code:
	// return fuzzLoadFunc(data)
	// return fuzzUnmarshall(data)
	return fuzzEnv(data)
}

func fuzzEnv(data []byte) int {
	dataString := string(data)
	dataSliceStrings := strings.Split(dataString, "\n")
	envBytes, contextBytes, funcBytes := []byte(dataSliceStrings[0]), []byte(dataSliceStrings[1]), []byte(dataSliceStrings[2])

	env := &config.Env{}
	json.Unmarshal(envBytes, env)
	function := web.Logout(env)

	context := &gin.Context{}
	json.Unmarshal(contextBytes, context)
	funcInt := binary.BigEndian.Uint64(funcBytes)

	switch funcInt % 21 {
	case 1:
		function = web.SessionTempl(env)
	case 3:
		function = web.LiveSessionTempl(env)
	case 4:
		function = web.UserTempl(env)
	case 5:
		function = web.AuthRuleTempl(env)
	case 6:
		function = web.NoaccessTempl(env)
	case 7:
		function = web.OtpTempl(env)
	case 8:
		function = web.LiveSession(env)
	case 9:
		function = web.User(env)
	case 10:
		function = web.UpdateUser(env)
	case 11:
		function = web.DownloadKey(env)
	case 12:
		function = web.AuthRule(env)
	case 13:
		function = web.UpdateAuthRule(env)
	case 14:
		function = web.DeleteAuthRule(env)
	case 15:
		function = web.LiveSessionWS(env)
	case 16:
		function = web.DisconnectLiveSession(env)
	case 17:
		function = web.SessionID(env)
	case 18:
		function = web.CheckOtp(env)
	case 19:
		function = web.SetupOtp(env)
	case 20:
		function = web.SetupOtpTempl(env)
	default:
		fmt.Printf("fuzzing Logout function")
	}
	function(context)
	return 0
}

func fuzzUnmarshall(data []byte) int {
	inputString := string(data)
	cast, err := asciicast.UnmarshalCast(inputString)
	if err != nil {
		return 0
	}
	if cast == nil {
		return 1
	}

	fileFormat, err := cast.Marshal()
	if err != nil {
		return 0
	}
	if &fileFormat == nil {
		return 1
	}
	return 0
}

func fuzzLoadFunc(data []byte) int {

	// fuzzer return 1 when/if program returns nil
	// fuzzer should return 0 when/if program returns non-nil env variable.
	flag.Parse()
	//write byte stream into config.yml file and then call load func with predetermined inputs that make sense
	err := ioutil.WriteFile("bastion/config/config.yml", data, 0644)
	if err != nil {
		// can't successfully write byte stream to file
		return -1
	}
	env := config.Load(*forceCerts, *webAddr, *sshAddr, *sshProxyAddr, *monAddr)
	if env == nil {
		return 1
	}
	return 0
}
