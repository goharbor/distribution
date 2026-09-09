module github.com/docker/distribution

go 1.26.5

require (
	github.com/Azure/azure-sdk-for-go v16.2.1+incompatible
	github.com/FZambia/sentinel v1.1.0
	github.com/Shopify/logrus-bugsnag v0.0.0-20171204204709-577dee27f20d
	github.com/aws/aws-sdk-go v1.55.8
	github.com/bshuster-repo/logrus-logstash-hook v1.1.0
	github.com/bugsnag/bugsnag-go v1.0.3-0.20141110184014-b1d153021fcd
	github.com/denverdino/aliyungo v0.0.0-20161108032828-afedced274aa
	github.com/distribution/reference v0.5.0
	github.com/docker/go-metrics v0.0.0-20180209012529-399ea8c73916
	github.com/docker/libtrust v0.0.0-20150114040149-fa567046d9b1
	github.com/gomodule/redigo v1.8.8
	github.com/gorilla/handlers v1.5.2
	github.com/gorilla/mux v1.8.0
	github.com/mitchellh/mapstructure v0.0.0-20150528213339-482a9fd5fa83
	github.com/ncw/swift v1.0.40
	github.com/opencontainers/go-digest v1.0.0
	github.com/opencontainers/image-spec v1.0.2
	github.com/sirupsen/logrus v1.9.4
	github.com/spf13/cobra v1.10.2
	github.com/yvasiyarov/gorelic v0.0.7-0.20141212073537-a9bba5b9ab50
	golang.org/x/crypto v0.55.0
	golang.org/x/oauth2 v0.36.0
	google.golang.org/api v0.0.0-20160322025152-9bf6e6e569ff
	google.golang.org/cloud v0.0.0-20151119220103-975617b05ea8
	gopkg.in/check.v1 v1.0.0-20201130134442-10cb98267c6c
	gopkg.in/yaml.v2 v2.4.0
	rsc.io/letsencrypt v0.0.0-20161112011014-e770c10b0f1a
)

require (
	cloud.google.com/go/compute/metadata v0.9.0 // indirect
	github.com/Azure/go-autorest v14.2.0+incompatible // indirect
	github.com/Azure/go-autorest/autorest v0.11.30 // indirect
	github.com/Azure/go-autorest/autorest/adal v0.9.24 // indirect
	github.com/Azure/go-autorest/autorest/date v0.3.0 // indirect
	github.com/Azure/go-autorest/logger v0.2.1 // indirect
	github.com/Azure/go-autorest/tracing v0.6.0 // indirect
	github.com/beorn7/perks v1.0.1 // indirect
	github.com/bitly/go-simplejson v0.5.1 // indirect
	github.com/bugsnag/osext v0.0.0-20130617224835-0dd3f918b21b // indirect
	github.com/bugsnag/panicwrap v0.0.0-20151223152923-e2c28503fcd0 // indirect
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/davecgh/go-spew v1.1.2-0.20180830191138-d8f796af33cc // indirect
	github.com/dnaeon/go-vcr v1.2.0 // indirect
	github.com/felixge/httpsnoop v1.0.4 // indirect
	github.com/golang-jwt/jwt/v4 v4.5.2 // indirect
	github.com/inconshreveable/mousetrap v1.1.0 // indirect
	github.com/jmespath/go-jmespath v0.4.0 // indirect
	github.com/kr/pretty v0.3.1 // indirect
	github.com/kr/text v0.2.0 // indirect
	github.com/marstr/guid v1.1.0 // indirect
	github.com/miekg/dns v1.0.15 // indirect
	github.com/mitchellh/osext v0.0.0-20151018003038-5e2d6d41470f // indirect
	github.com/munnerz/goautoneg v0.0.0-20191010083416-a7dc8b61c822 // indirect
	github.com/pmezard/go-difflib v1.0.1-0.20181226105442-5d4384ee4fb2 // indirect
	github.com/prometheus/client_golang v1.24.1 // indirect
	github.com/prometheus/client_model v0.6.2 // indirect
	github.com/prometheus/common v0.70.1 // indirect
	github.com/prometheus/procfs v0.21.1 // indirect
	github.com/rogpeppe/go-internal v1.14.1 // indirect
	github.com/satori/go.uuid v1.2.0 // indirect
	github.com/spf13/pflag v1.0.10 // indirect
	github.com/xenolf/lego v0.3.2-0.20160613233155-a9d8cec0e656 // indirect
	github.com/yvasiyarov/go-metrics v0.0.0-20140926110328-57bccd1ccd43 // indirect
	github.com/yvasiyarov/newrelic_platform_go v0.0.0-20140908184405-b21fdbd4370f // indirect
	golang.org/x/net v0.58.0 // indirect
	golang.org/x/sys v0.47.0 // indirect
	golang.org/x/text v0.41.0 // indirect
	golang.org/x/time v0.15.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20260526163538-3dc84a4a5aaa // indirect
	google.golang.org/grpc v1.83.2 // indirect
	google.golang.org/protobuf v1.36.12 // indirect
	gopkg.in/square/go-jose.v1 v1.1.2 // indirect
)

replace rsc.io/letsencrypt => github.com/dmcgowan/letsencrypt v0.0.0-20161112011014-e770c10b0f1a
