# Note: to make a plugin compatible with a binary built in debug mode, add `-gcflags='all=-N -l'`

PLUGIN_OS ?= linux
PLUGIN_ARCH ?= amd64

plugin_azuread: bin/$(PLUGIN_OS)$(PLUGIN_ARCH)/azuread.so

bin/$(PLUGIN_OS)$(PLUGIN_ARCH)/azuread.so: pkg/plugins/glauth-azuread/azuread.go
	GOOS=$(PLUGIN_OS) GOARCH=$(PLUGIN_ARCH) go build ${TRIM_FLAGS} -ldflags "${BUILD_VARS}" -buildmode=plugin -o $@ $^

plugin_azuread_linux_amd64:
	PLUGIN_OS=linux PLUGIN_ARCH=amd64 make plugin_azuread

plugin_azuread_linux_arm64:
	PLUGIN_OS=linux PLUGIN_ARCH=arm64 make plugin_azuread

plugin_azuread_darwin_amd64:
	PLUGIN_OS=darwin PLUGIN_ARCH=amd64 make plugin_azuread

plugin_azuread_darwin_arm64:
	PLUGIN_OS=darwin PLUGIN_ARCH=arm64 make plugin_azuread

release-glauth-azuread:
	@P=azuread M=pkg/plugins/glauth-azuread make releaseplugin
