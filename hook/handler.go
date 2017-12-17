package hook

import (
	"bufio"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/hex"
	"io"
	"io/ioutil"
	"net/http"
	"os/exec"
	"path"
	"sync"

	log "github.com/sirupsen/logrus"

	"github.com/AdamJacobMuller/weblogrus"
	"github.com/adamjacobmuller/captain/lib"
	"github.com/gocraft/web"
)

func (c *Context) ValidateGithubHMAC(w web.ResponseWriter, req *web.Request, next web.NextMiddlewareFunc) {
	if req.Method != "POST" {
		http.Error(w, "405 Method not allowed", http.StatusMethodNotAllowed)
		log.WithFields(log.Fields{
			"method": req.Method,
		}).Error("bad request method")
		return
	}

	eventType := req.Header.Get("X-GitHub-Event")
	if eventType == "" {
		http.Error(w, "400 Missing X-GitHub-Event Header", http.StatusBadRequest)
		log.WithFields(log.Fields{}).Error("Missing X-GitHub-Event Header")
		return
	}
	if eventType != "push" && eventType != "pull_request" {
		http.Error(w, "400 Unknown Event Type "+eventType, http.StatusBadRequest)
		log.WithFields(log.Fields{}).Error("Unknown Event Type")
		return
	}

	body, err := ioutil.ReadAll(req.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		log.WithFields(log.Fields{
			"err": err,
		}).Error("ioutil.ReadAll failed")
		return
	}

	if c.Secret != "" {
		sig := req.Header.Get("X-Hub-Signature")

		if sig == "" {
			http.Error(w, "403 Missing X-Hub-Signature required for HMAC verification", http.StatusForbidden)
			log.WithFields(log.Fields{}).Error("Missing X-Hub-Signature required for HMAC verification")
			return
		}

		mac := hmac.New(sha1.New, []byte(c.Secret))
		mac.Write(body)
		expectedMAC := mac.Sum(nil)
		expectedSig := "sha1=" + hex.EncodeToString(expectedMAC)
		if !hmac.Equal([]byte(expectedSig), []byte(sig)) {
			http.Error(w, "403 Forbidden - HMAC verification failed", http.StatusForbidden)
			log.WithFields(log.Fields{}).Error("HMAC verification failed")
			return
		}
	}
	next(w, req)
}
func log_rc(le *log.Entry, rc io.ReadCloser, wg *sync.WaitGroup) {
	scanner := bufio.NewScanner(lib.NewNormaliser(rc))
	for scanner.Scan() {
		le.Info(scanner.Text())
	}
	rc.Close()
	wg.Done()
}

func (c *Context) Trigger(rw web.ResponseWriter, req *web.Request) {
	name := req.PathParams["name"]

	hookdir := path.Join(c.HookDir, name)

	files, err := ioutil.ReadDir(hookdir)
	if err != nil {
		http.Error(rw, "502 ISE", http.StatusInternalServerError)
		log.Error(err)
		return
	}

	for _, file := range files {
		hookfile := path.Join(c.HookDir, name, file.Name())

		wg := &sync.WaitGroup{}
		cmd := exec.Command(hookfile)
		cmd.Dir = hookdir

		stdout, err := cmd.StdoutPipe()
		if err != nil {
			http.Error(rw, "502 ISE", http.StatusInternalServerError)
			log.Error(err)
			return
		}
		wg.Add(1)
		go log_rc(log.WithFields(log.Fields{"output": "stdout"}), stdout, wg)

		stderr, err := cmd.StderrPipe()
		if err != nil {
			http.Error(rw, "502 ISE", http.StatusInternalServerError)
			log.Error(err)
			return
		}
		wg.Add(1)
		go log_rc(log.WithFields(log.Fields{"output": "stderr"}), stderr, wg)

		err = cmd.Start()
		if err != nil {
			http.Error(rw, "502 ISE", http.StatusInternalServerError)
			log.Error(err)
			return
		}
		wg.Wait()
	}
	log.Info("trigger completed")
	http.Error(rw, "200 Trigger Completed", http.StatusOK)
}

type Context struct {
	Secret  string
	HookDir string
}

func NewServer(hookDir string, secret string) *web.Router {

	router := web.New(Context{})
	x := weblogrus.NewMiddleware()
	router.Middleware(x.ServeHTTP)
	router.Middleware(func(ctx *Context, resp web.ResponseWriter,
		req *web.Request, next web.NextMiddlewareFunc) {
		ctx.Secret = secret
		ctx.HookDir = hookDir
		next(resp, req)
	})
	router.Middleware((*Context).ValidateGithubHMAC)
	router.Post("/trigger/:name", (*Context).Trigger)
	return router
}
