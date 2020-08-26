package mate

import (
	"fmt"
	"log"
	"net/http"
)

type Server struct {
	mux *http.ServeMux
}

func NewServer() *Server {
	s := Server{
		mux: http.NewServeMux(),
	}
	s.mux.HandleFunc("/clash/provider/gfwlist", s.wrapperClashHandler(newGfwlistProvider().Handle))
	return &s
}

func (s *Server) wrapperClashHandler(f func(wr http.ResponseWriter)) http.HandlerFunc {
	return func(wr http.ResponseWriter, r *http.Request) {
		wr.Header().Set("Content-Type", "application/yaml")
		wr.Header().Set("cache-control", "no-cache")
		f(wr)
	}
}

func (s *Server) Start(port int) error {
	log.Printf("Server listened on %d\n", port)
	return http.ListenAndServe(fmt.Sprintf(":%d", port), s.mux)
}
