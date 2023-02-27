package main

import (
	"crypto/tls"
	"flag"
	"log"
	"os"
	"sort"

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
var bind_user string
var bind_pass string
var ldap_conn *ldap.Conn

const DefaultConfig string = "/config.yaml"

func checkRequiredField(field string, value string) {
	if value == "" {
		log.Fatalf("Missing required field '%s' in YAML file", field)
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

func get_users(ldan_conn *ldap.Conn, config Config) bool {
	searchRequest_users := ldap.NewSearchRequest(
		config.Ldap.BaseDn,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		config.Ldap.UserFilter,
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

func main() {
	config_path := flag.String("config", DefaultConfig, "Config path")
	flag.Parse()
	data, err := os.ReadFile(*config_path)
	if err != nil {
		panic(err)
	}

	var config Config

	err = yaml.Unmarshal(data, &config)
	if err != nil {
		panic(err)
	}

	ldap_host := config.Ldap.Host
	bind_user = config.Ldap.Username
	bind_pass = config.Ldap.Password
	checkRequiredField("ldap.username", config.Ldap.Username)
	checkRequiredField("ldap.password", config.Ldap.Password)
	checkRequiredField("ldap.host", config.Ldap.Host)
	checkRequiredField("ldap.base_dn", config.Ldap.BaseDn)
	checkRequiredField("ldap.user_filter", config.Ldap.UserFilter)
	checkRequiredField("server.host", config.Server.Host)
	checkRequiredField("server.port", config.Server.Port)

	ldap_conn, err = ldap.DialURL(ldap_host)
	if err != nil {
		log.Fatal(err)
	}
	defer ldap_conn.Close()

	if config.Ldap.TLS.Enabled {
		err = ldap_conn.StartTLS(&tls.Config{InsecureSkipVerify: config.Ldap.TLS.SkipVerify})
		if err != nil {
			log.Fatal(err)
		}
	}
	err = ldap_conn.Bind(bind_user, bind_pass)
	if err != nil {
		log.Fatal(err)
	}
	_ = get_users(ldap_conn, config)
	cred := &MyCredentialStore{}
	server := socks5.NewServer(
		//socks5.WithCredential(socks5.StaticCredentials{"username": "password",}),
		socks5.WithAuthMethods([]socks5.Authenticator{socks5.UserPassAuthenticator{Credentials: cred}}),
		socks5.WithLogger(
			socks5.NewLogger(log.New(os.Stdout, "", log.LstdFlags)),
		),
	)
	address := config.Server.Host + ":" + config.Server.Port
	log.Printf("Starting socks5 server at %s", address)
	if err := server.ListenAndServe("tcp", address); err != nil {
		panic(err)
	}
}
