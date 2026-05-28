module github.com/docker/distribution

go 1.25.0

require (
	github.com/Azure/azure-sdk-for-go v16.2.1+incompatible
	github.com/FZambia/sentinel v1.1.0
	github.com/Shopify/logrus-bugsnag v0.0.0-20171204204709-577dee27f20d
	github.com/aws/aws-sdk-go v1.55.8
	github.com/bshuster-repo/logrus-logstash-hook v0.0.0-20170517171303-d2c0ecc1836d
	github.com/bugsnag/bugsnag-go v1.0.3-0.20141110184014-b1d153021fcd
	github.com/denverdino/aliyungo v0.0.0-20161108032828-afedced274aa
	github.com/distribution/reference v0.5.0
	github.com/docker/go-metrics v0.0.0-20180209012529-399ea8c73916
	github.com/docker/libtrust v0.0.0-20150114040149-fa567046d9b1
	github.com/gomodule/redigo v1.8.8
	github.com/gorilla/handlers v0.0.0-20150720190736-60c7bfde3e33
	github.com/gorilla/mux v1.3.1-0.20170228224354-599cba5e7b61
	github.com/mitchellh/mapstructure v0.0.0-20150528213339-482a9fd5fa83
	github.com/ncw/swift v1.0.40
	github.com/opencontainers/go-digest v1.0.0
	github.com/opencontainers/image-spec v1.0.2
	github.com/sirupsen/logrus v1.0.1-0.20170620144510-3d4380f53a34
	github.com/spf13/cobra v1.10.2
	github.com/yvasiyarov/gorelic v0.0.7-0.20141212073537-a9bba5b9ab50
	golang.org/x/crypto v0.52.0
	golang.org/x/oauth2 v0.0.0-20160304213135-045497edb623
	google.golang.org/api v0.0.0-20160322025152-9bf6e6e569ff
	google.golang.org/cloud v0.0.0-20151119220103-975617b05ea8
	gopkg.in/check.v1 v1.0.0-20141024133853-64131543e789
	gopkg.in/yaml.v3 v3.0.1
	rsc.io/letsencrypt v0.0.0-20161112011014-e770c10b0f1a
)

require (
	github.com/Azure/go-autorest v10.8.1+incompatible // indirect
	github.com/beorn7/perks v0.0.0-20160804104726-4c0e84591b9a // indirect
	github.com/bitly/go-simplejson v0.5.1 // indirect
	github.com/bugsnag/osext v0.0.0-20130617224835-0dd3f918b21b // indirect
	github.com/bugsnag/panicwrap v0.0.0-20151223152923-e2c28503fcd0 // indirect
	github.com/dgrijalva/jwt-go v3.2.0+incompatible // indirect
	github.com/dnaeon/go-vcr v1.2.0 // indirect
	github.com/golang/protobuf v0.0.0-20160321223353-8d92cf5fc15a // indirect
	github.com/gorilla/context v1.1.2 // indirect
	github.com/inconshreveable/mousetrap v1.1.0 // indirect
	github.com/jmespath/go-jmespath v0.4.0 // indirect
	github.com/marstr/guid v1.1.0 // indirect
	github.com/matttproud/golang_protobuf_extensions v1.0.1 // indirect
	github.com/miekg/dns v0.0.0-20161122061214-271c58e0c14f // indirect
	github.com/mitchellh/osext v0.0.0-20151018003038-5e2d6d41470f // indirect
	github.com/prometheus/client_golang v0.9.0-pre1.0.20180209125602-c332b6f63c06 // indirect
	github.com/prometheus/client_model v0.0.0-20171117100541-99fa1f4be8e5 // indirect
	github.com/prometheus/common v0.0.0-20180110214958-89604d197083 // indirect
	github.com/prometheus/procfs v0.0.0-20180125133057-cb4147076ac7 // indirect
	github.com/satori/go.uuid v1.2.0 // indirect
	github.com/spf13/pflag v1.0.10 // indirect
	github.com/xenolf/lego v0.3.2-0.20160613233155-a9d8cec0e656 // indirect
	github.com/yvasiyarov/go-metrics v0.0.0-20140926110328-57bccd1ccd43 // indirect
	github.com/yvasiyarov/newrelic_platform_go v0.0.0-20140908184405-b21fdbd4370f // indirect
	golang.org/x/net v0.54.0 // indirect
	golang.org/x/sys v0.45.0 // indirect
	golang.org/x/text v0.37.0 // indirect
	golang.org/x/time v0.0.0-20160202183820-a4bde1265759 // indirect
	google.golang.org/appengine v0.0.0-20160301025000-12d5545dc1cf // indirect
	google.golang.org/grpc v0.0.0-20160317175043-d3ddb4469d5a // indirect
	gopkg.in/square/go-jose.v1 v1.0.1 // indirect
)

replace rsc.io/letsencrypt => github.com/dmcgowan/letsencrypt v0.0.0-20161112011014-e770c10b0f1a
