package main

import (
	"crypto/tls"
	"flag"
	"log"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/go-ldap/ldap/v3"
	"github.com/things-go/go-socks5"
	"gopkg.in/yaml.v3"
)

type MyCredentialStore struct {
	Credentials map[string]*CachedCredentials
	UserDNList  map[string]string
	mu          sync.Mutex
}

type CachedCredentials struct {
	Password    string
	LastUpdated time.Time
}

func (s *MyCredentialStore) Valid(user, password, userAddr string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
    log.Printf("User '%s' connecting from address '%s'", user, userAddr)
    if password == "" {
        return false
    }
	if cachedCreds, ok := s.Credentials[user]; ok {
		if time.Since(cachedCreds.LastUpdated) <= cacheUpdateInterval {
			return cachedCreds.Password == password
		}
	}
	result := checkUser(user, s.UserDNList)
	if result != "" {
		ldapConn := getLdapConn()
		bindRes := ldapConn.Bind(result, password)
		success := bindRes == nil
		log.Printf("Checking LDAP server for user '%s'", user)
		if success {
			log.Printf("User '%s' successfully authenticated against LDAP server", user)
			s.updateCredentials(user, password)
		}
		return success
	}
	log.Printf("User '%s' not found on LDAP server", user)
	return false
}

func (s *MyCredentialStore) updateCredentials(user, password string) {
	s.Credentials[user] = &CachedCredentials{
		Password:    password,
		LastUpdated: time.Now(),
	}
}

func (s *MyCredentialStore) updateUserList() {
	ldapConn := getLdapConn()
	err := ldapConn.Bind(bindUser, bindPass)
	if err != nil {
		log.Fatal(err)
	}
	searchRequestUsers := ldap.NewSearchRequest(
		ldapBaseDN,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		ldapUserFilter,
		[]string{"uid"},
		nil,
	)
	searchResultUsers, err := ldapConn.Search(searchRequestUsers)
	if err != nil {
		panic(err)
	}
	for _, entry := range searchResultUsers.Entries {
		log.Printf("Updating user list for user '%s'", entry.GetAttributeValue("uid"))
		s.UserDNList[entry.GetAttributeValue("uid")] = entry.DN
	}
}

type Config struct {
	UpdateInterval	int `default:"10" yaml:"update_interval"`
	Ldap struct {
		Host        string `yaml:"host"`
		TLS         bool   `yaml:"tls"`
		TLSSkip     bool   `default:"false" yaml:"tls_skip_verify"`
		BaseDN      string `yaml:"base_dn"`
		UserFilter  string `yaml:"user_filter"`
		Username    string `yaml:"username"`
		Password    string `yaml:"password"`
	} `yaml:"ldap"`
	Server struct {
		Host string `yaml:"host"`
		Port string `yaml:"port"`
	} `yaml:"server"`
}

var (
	bindUser, bindPass, ldapHost, ldapBaseDN, ldapUserFilter, serverPort, serverHost string
	ldapTLSEnable, ldapTLSSkipVerify bool
	cacheUpdateInterval time.Duration
	updateInterval int
)

func checkRequiredField(field, value string) {
	if value == "" {
		log.Fatalf("Missing required field '%s'", field)
	}
}

func checkUser(username string, userDNList map[string]string) string {
	DN, found := userDNList[username]
	if found {
		return DN
	}
	return ""
}

func getEnv(key, fallback string ) string {
	if value, ok := os.LookupEnv(key); ok {
		return value
	}
	return fallback
}

func getEnvInt(key string, fallback int) int {
	s, ok := os.LookupEnv(key)
	if !ok {
		return fallback
	}
    v, err := strconv.Atoi(s)
    if err != nil {
        return fallback
    }
    return v
}

func getLdapConn() *ldap.Conn {
	ldapConn, err := ldap.DialURL(ldapHost)
	if err != nil {
		log.Fatal(err)
	}
	if ldapTLSEnable {
		err = ldapConn.StartTLS(&tls.Config{InsecureSkipVerify: ldapTLSSkipVerify, MinVersion: tls.VersionTLS13})
		if err != nil {
			log.Fatal(err)
		}
	}
	return ldapConn
}

func main() {
	configPath := flag.String("config", "envs", "Config path")
	flag.Parse()
	if *configPath == "envs" {
		ldapHost = getEnv("LDAP_HOST", "ldap://ldap.host:389")
		bindUser = getEnv("LDAP_USER", "cn=admin,ou=people,dc=example,dc=com")
		bindPass = getEnv("LDAP_PASS", "password")
		ldapBaseDN = getEnv("LDAP_BASE_DN", "ou=people,dc=example,dc=com")
		ldapUserFilter = getEnv("LDAP_USER_FILTER", "(&(objectClass=person)(memberOf=cn=socks,ou=groups,dc=example,dc=com))")
		ldapTLSEnable, _ = strconv.ParseBool(getEnv("TLS_ENABLED", "false"))
		ldapTLSSkipVerify, _ = strconv.ParseBool(getEnv("TLS_SKIP_VERIFY", "false"))
		serverPort = getEnv("SERVER_PORT", "1080")
		serverHost = getEnv("SERVER_HOST", "0.0.0.0")
		updateInterval = getEnvInt("UPDATE_interval",10)
		checkRequiredField("LDAP_HOST", ldapHost)
		checkRequiredField("LDAP_USER", bindUser)
		checkRequiredField("LDAP_PASS", bindPass)
		checkRequiredField("LDAP_BASE_DN", ldapBaseDN)
		checkRequiredField("LDAP_USER_FILTER", ldapUserFilter)
		checkRequiredField("SERVER_HOST", serverHost)
		checkRequiredField("SERVER_PORT", serverPort)
	} else {
		data, err := os.ReadFile(*configPath)
		if err != nil {
			panic(err)
		}
		var config Config
		err = yaml.Unmarshal(data, &config)
		if err != nil {
			panic(err)
		}
		ldapHost = config.Ldap.Host
		bindUser = config.Ldap.Username
		bindPass = config.Ldap.Password
		ldapBaseDN = config.Ldap.BaseDN
		ldapUserFilter = config.Ldap.UserFilter
		ldapTLSEnable = config.Ldap.TLS
		ldapTLSSkipVerify = config.Ldap.TLSSkip
		serverHost = config.Server.Host
		serverPort = config.Server.Port
		updateInterval = config.UpdateInterval
		checkRequiredField("ldap.host", ldapHost)
		checkRequiredField("ldap.username", bindUser)
		checkRequiredField("ldap.password", bindPass)
		checkRequiredField("ldap.base_dn", ldapBaseDN)
		checkRequiredField("ldap.user_filter", ldapUserFilter)
		checkRequiredField("server.host", serverHost)
		checkRequiredField("server.port", serverPort)
	}
	cacheUpdateInterval = time.Duration(updateInterval) * time.Minute
	credentialsCache := make(map[string]*CachedCredentials)
	UserDNList := make(map[string]string)
	cred := &MyCredentialStore{Credentials: credentialsCache, UserDNList: UserDNList}

	go func() {
		for {
			time.Sleep(time.Minute)
			cred.mu.Lock()
			for user, cachedCreds := range cred.Credentials {
				if time.Since(cachedCreds.LastUpdated) > cacheUpdateInterval {
					delete(cred.Credentials, user)
				}
			}
			cred.mu.Unlock()
		}
	}()

	cred.updateUserList()
	server := socks5.NewServer(
		socks5.WithAuthMethods([]socks5.Authenticator{socks5.UserPassAuthenticator{Credentials: cred}}),
	)
	address := serverHost + ":" + serverPort
	log.Printf("Starting socks5 server at %s", address)
	if err := server.ListenAndServe("tcp", address); err != nil {
		panic(err)
	}
}
