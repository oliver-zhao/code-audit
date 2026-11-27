package main

import (
	"net/http"
	"os"
	"os/exec"

	"github.com/go-chi/chi/v5"
	"github.com/gofiber/fiber/v2"
	"github.com/gorilla/mux"
	"github.com/julienschmidt/httprouter"
	"github.com/labstack/echo/v4"
)

func chiDoc(w http.ResponseWriter, r *http.Request) {
	os.ReadFile("/srv/docs/" + chi.URLParam(r, "doc"))
}

func deleteUpload(w http.ResponseWriter, r *http.Request) {
	os.Remove("/srv/uploads/" + r.PathValue("name"))
}

func routerDoc(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	os.Open("/srv/docs/" + ps.ByName("doc"))
}

func purgeCache(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	exec.Command("rm", "-f", "/srv/cache/"+vars["key"]).Run()
}

func echoLookup(c echo.Context) error {
	return exec.Command("nslookup", c.QueryParam("host")).Run()
}

func fiberNext(c *fiber.Ctx) error {
	return c.Redirect(c.Query("next"))
}

func echoFile(c echo.Context) error {
	return c.File("/srv/files/" + c.Param("name"))
}

func formNext(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, r.Form["next"][0], http.StatusFound)
}
