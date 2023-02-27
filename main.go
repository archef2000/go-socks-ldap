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
	result := check_user(user)
	if result != "" {
		if len(name_list) > 0 {
			pass_ok := check_pass(user, password)
			if pass_ok {
				return true
			}
		}
		log.Printf("User '%s' connecting", user)
		ldap_conn := getLdapConn(ldap_host, ldap_tls_enable, ldap_tls_skip_verify)
		bind_res := ldap_conn.Bind(result, password)
		success := bind_res == nil
		_ = ldap_conn.Bind(bind_user, bind_pass)
		if success {
			pass_list = append(pass_list, password)
			name_list = append(name_list, user)
			log.Printf("User '%s' successfully authenticated", user)
		}
		return success
	} else {
		log.Printf("User '%s' connecting", user)
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

var pass_list []string
var name_list []string
var users_list []string
var dn_list []string
var (
	bind_user, bind_pass, ldap_host, ldap_base_dn, ldap_user_filter, server_port, server_host string
)

var (
	ldap_tls_enable, ldap_tls_skip_verify bool
)

func checkRequiredField(field string, value string) {
	if value == "" {
		log.Fatalf("Missing required field '%s'", field)
	}
}

func check_user(username string) string {
	index := sort.SearchStrings(users_list, username)
	if index < len(users_list) && users_list[index] == username {
		return dn_list[index]
	} else {
		return ""
	}
}

func check_pass(username string, password string) bool {
	index := sort.SearchStrings(name_list, username)
	if index < len(users_list) && users_list[index] == username {
		return pass_list[index] == password
	} else {
		return false
	}
}

func get_users(ldap_base_dn string, ldap_user_filter string) bool {
	ldap_conn := getLdapConn(ldap_host, ldap_tls_enable, ldap_tls_skip_verify)
	err := ldap_conn.Bind(bind_user, bind_pass)
	if err != nil {
		log.Fatal(err)
	}
	searchRequest_users := ldap.NewSearchRequest(
		ldap_base_dn,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		ldap_user_filter,
		[]string{"uid"},
		nil,
	)
	users_list = users_list[:0]
	dn_list = dn_list[:0]
	searchResult_users, err := ldap_conn.Search(searchRequest_users)
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

func getLdapConn(ldap_host string, ldap_tls_enable bool, ldap_tls_skip_verify bool) *ldap.Conn {
	ldap_conn, err := ldap.DialURL(ldap_host)
	if err != nil {
		log.Fatal(err)
	}
	if ldap_tls_enable {
		err = ldap_conn.StartTLS(&tls.Config{InsecureSkipVerify: ldap_tls_skip_verify})
		if err != nil {
			log.Fatal(err)
		}
	}
	return ldap_conn
}

func main() {
	config_path := flag.String("config", "envs", "Config path")
	flag.Parse()
	if *config_path == "envs" {
		ldap_host = getEnv("LDAP_HOST", "ldap://ldap.host:389")
		bind_user = getEnv("LDAP_USER", "cn=admin,ou=people,dc=example,dc=com")
		bind_pass = getEnv("LDAP_PASS", "password")
		ldap_base_dn = getEnv("LDAP_BASE_DN", "ou=people,dc=example,dc=com")
		ldap_user_filter = getEnv("LDAP_USER_FILTER", "(&(objectClass=person)(memberOf=cn=socks,ou=groups,dc=example,dc=com))")
		ldap_tls_enable, _ = strconv.ParseBool(getEnv("TLS_ENABLED", "false"))
		ldap_tls_skip_verify, _ = strconv.ParseBool(getEnv("TLS_SKIP_VERIFY", "false"))
		server_port = getEnv("SERVER_PORT", "1080")
		server_host = getEnv("SERVER_HOST", "0.0.0.0")
		checkRequiredField("LDAP_HOST", ldap_host)
		checkRequiredField("LDAP_USER", bind_user)
		checkRequiredField("LDAP_PASS", bind_pass)
		checkRequiredField("LDAP_BASE_DN", ldap_base_dn)
		checkRequiredField("LDAP_USER_FILTER", ldap_user_filter)
		checkRequiredField("SERVER_HOST", server_host)
		checkRequiredField("SERVER_PORT", server_port)
	} else {
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
	}
	_ = get_users(ldap_base_dn, ldap_user_filter)
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
