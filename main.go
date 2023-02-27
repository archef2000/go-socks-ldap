package main

import (
	"crypto/tls"
	"flag"
	"log"
	"os"
	"sort"
	"strconv"

	"github.com/go-ldap/ldap/v3"
	"github.com/things-go/go-socks5"
	"gopkg.in/yaml.v3"
)

type MyCredentialStore struct{}

func (s *MyCredentialStore) Valid(user, password, userAddr string) bool {
	log.Printf("User '%s' connecting", user)
	result := check_user(user)
	if result != "" {
		success := ldap_conn.Bind(result, password) == nil
		_ = ldap_conn.Bind(bind_user, bind_pass)
		if success {
			log.Printf("User '%s' successfully authenticated", user)
		}
		return success
	} else {
		return false
	}
}

type Config struct {
	Ldap struct {
		Host string `yaml:"host"`
		TLS  struct {
			Enabled    bool `yaml:"enabled"`
			SkipVerify bool `yaml:"skip_verify"`
		} `yaml:"tls"`
		BaseDn     string `yaml:"base_dn"`
		UserFilter string `yaml:"user_filter"`
		Username   string `yaml:"username"`
		Password   string `yaml:"password"`
	} `yaml:"ldap"`
	Server struct {
		Host string `yaml:"host"`
		Port string `yaml:"port"`
	} `yaml:"server"`
}

var users_list []string
var dn_list []string
var ldap_conn *ldap.Conn
var (
	bind_user, bind_pass, ldap_host, ldap_base_dn, ldap_user_filter, server_port, server_host string
)

var (
	ldap_tls_enable, ldap_tls_skip_verify bool
)

const DefaultConfig string = "/config.yaml"

func checkRequiredField(field string, value string) {
	if value == "" {
		log.Fatalf("Missing required field '%s'", field)
	}
}

func check_user(target string) string {
	index := sort.SearchStrings(users_list, target)
	if index < len(users_list) && users_list[index] == target {
		return dn_list[index]
	} else {
		return ""
	}
}
func get_users(ldan_conn *ldap.Conn, ldap_base_dn string, ldap_user_filter string) bool {
	searchRequest_users := ldap.NewSearchRequest(
		ldap_base_dn,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		ldap_user_filter,
		[]string{"uid"},
		nil,
	)
	users_list = users_list[:0]
	dn_list = dn_list[:0]
	searchResult_users, err := ldan_conn.Search(searchRequest_users)
	if err != nil {
		panic(err)
	}
	for _, entry := range searchResult_users.Entries {
		users_list = append(users_list, entry.GetAttributeValue("uid"))
		dn_list = append(dn_list, entry.DN)
	}
	return true
}

func getEnv(key string, fallback string) string {
	if value, ok := os.LookupEnv(key); ok {
		return value
	}
	return fallback
}

func main() {
	config_path := flag.String("config", DefaultConfig, "Config path")
	flag.Parse()
	if *config_path == "envs" {
		data, err := os.ReadFile(*config_path)
		if err != nil {
			panic(err)
		}
		var config Config
		err = yaml.Unmarshal(data, &config)
		if err != nil {
			panic(err)
		}
		ldap_host = config.Ldap.Host
		bind_user = config.Ldap.Username
		bind_pass = config.Ldap.Password
		ldap_base_dn = config.Ldap.BaseDn
		ldap_user_filter = config.Ldap.UserFilter
		ldap_tls_enable = config.Ldap.TLS.Enabled
		ldap_tls_skip_verify = config.Ldap.TLS.SkipVerify
		server_host = config.Server.Host
		server_port = config.Server.Port
		checkRequiredField("ldap.host", ldap_host)
		checkRequiredField("ldap.username", bind_user)
		checkRequiredField("ldap.password", bind_pass)
		checkRequiredField("ldap.base_dn", ldap_base_dn)
		checkRequiredField("ldap.user_filter", ldap_user_filter)
		checkRequiredField("server.host", server_host)
		checkRequiredField("server.port", server_port)
	} else {
		ldap_host = getEnv("LDAP_HOST", "ldap://ldap.host:389")
		bind_user = getEnv("LDAP_USER", "cn=admin,ou=people,dc=example,dc=com")
		bind_pass = getEnv("LDAP_PASS", "password")
		ldap_base_dn = getEnv("LDAP_BASE_DN", "ou=people,dc=example,dc=com")
		ldap_user_filter = getEnv("LDAP_USER_FILTER", "(&(objectClass=person)(memberOf=cn=socks,ou=groups,dc=example,dc=com))")
		ldap_tls_enable, _ = strconv.ParseBool(getEnv("TLS_ENABLED", "false"))
		ldap_tls_skip_verify, _ = strconv.ParseBool(getEnv("TLS_SKIP_VERIFY", "false"))
		server_port = getEnv("SERVER_PORT", "1080")
		server_host = getEnv("SERVER_HOST", "0.0.0.0")
		checkRequiredField("ldap.host", ldap_host)
		checkRequiredField("ldap.username", bind_user)
		checkRequiredField("ldap.password", bind_pass)
		checkRequiredField("ldap.base_dn", ldap_base_dn)
		checkRequiredField("ldap.user_filter", ldap_user_filter)
		checkRequiredField("server.host", server_host)
		checkRequiredField("server.port", server_port)
	}
	ldap_conn, err := ldap.DialURL(ldap_host)
	if err != nil {
		log.Fatal(err)
	}
	defer ldap_conn.Close()

	if ldap_tls_enable {
		err = ldap_conn.StartTLS(&tls.Config{InsecureSkipVerify: ldap_tls_skip_verify})
		if err != nil {
			log.Fatal(err)
		}
	}
	err = ldap_conn.Bind(bind_user, bind_pass)
	if err != nil {
		log.Fatal(err)
	}
	_ = get_users(ldap_conn, ldap_base_dn, ldap_user_filter)
	cred := &MyCredentialStore{}
	server := socks5.NewServer(
		//socks5.WithCredential(socks5.StaticCredentials{"username": "password",}),
		socks5.WithAuthMethods([]socks5.Authenticator{socks5.UserPassAuthenticator{Credentials: cred}}),
		socks5.WithLogger(
			socks5.NewLogger(log.New(os.Stdout, "", log.LstdFlags)),
		),
	)
	address := server_host + ":" + server_port
	log.Printf("Starting socks5 server at %s", address)
	if err := server.ListenAndServe("tcp", address); err != nil {
		panic(err)
	}
}
