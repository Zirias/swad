swad_VERSION=		0.1
swad_MODULES=		base64 \
			handler/root \
			http/header \
			http/headerset \
			http/httpcontext \
			http/httprequest \
			http/httpresponse \
			httpserver \
			main \
			mediatype \
			middleware/compress \
			middleware/cookies \
			middleware/pathparser \
			middleware/session \
			random \
			urlencode \
			util
swad_PKGDEPS=		posercore \
			zlib

$(call binrules,swad)
