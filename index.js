const module = (function() {
    const _nonce_counts = {}

    function _authenticate(method, path, credentials, headers) {
        const [ method, params ] = _get_authenticate_options(headers);
    
        if (method.toLowerCase() === "basic") {
            return _basic_authenticate(method, path, credentials, params);
        }
        
        if (method.toLowerCase() === "digest") {
            return _digest_authenticate(method, path, credentials, params);
        }

        return Promise.reject();
    }

    function _basic_authenticate(method, path, credentials, params) {
        return Promise.reject(); // TODO
    }

    function _digest_authenticate(method, path, credentials, params) {
        return new Promise((resolve, reject) => {
            const ha1 = encode("hex", hash("md5", [ credentials["username"], params["realm"], credentials["password"]].join(":")));
            const ha2 = encode("hex", hash("md5", [ method, path ].join(":")));
            const cnonce = encode("hex", random(16));
            const nc = (_nonce_counts[params["nonce"]] || 0) + 1;
            const response = encode("hex", hash("md5", [
                                ha1, params["nonce"], nc.toString(), cnonce, params["qop"], ha2
                            ].join(":")));
    
            resolve([
                "Digest",
                `username="${credentials["username"]}",`,
                `realm="${params["realm"]}",`,
                `nonce="${params["nonce"]}",`,
                `uri="${path}",`,
                `cnonce="${cnonce}",`,
                `nc=${nc},`,
                `qop="${params["qop"]}",`,
                `response="${response}"`
            ].join(" "));
    
            _nonce_counts[params["nonce"]] = nc;
        });
    }
    
    function _get_authenticate_options(headers) {
        for (let key in headers) {
            if (key.toLowerCase() === "www-authenticate") {
                return _parse_www_authenticate(headers[key]);
            }
        }
    }

    function _parse_www_authenticate(header) {
        const tokens = header.split(" ");
        const method = tokens[0], params = {};
    
        tokens.slice(1).join("").split(",").forEach((tuple) => {
            const tokens = tuple.split("=");
    
            if (tokens.length == 2) {
                params[tokens[0].trim()] = tokens[1].replace(/"/gi, "");
            }
        });
    
        return [ method, params ];
    }
    
    function _build_request_headers(options) {
        const headers = options["headers"] || {};
        const { authorization } = options;

        if (authorization) {
            headers["Authorization"] = authorization;
        }

        return headers;
    }

    return {
        request: function(url, method, options={}) {
            const headers = _build_request_headers(options);

            return fetch(url, {
                "method": method,
                "body": options["body"] || "",
                "headers": headers
            })
                .then((response) => {
                    if (response.status === 401) {
                        const credentials = options["credentials"] || {};
                        const { path } = parse("url", url);

                        _authenticate(method, path, credentials, response.headers)
                            .then((authorization) => {
                                return fetch(url, {
                                    "method": method,
                                    "body": options["body"] || "",
                                    "headers": Object.assign(headers, { 
                                        "Authorization": authorization 
                                    })
                                })
                                    .then((response) => {
                                        return Object.assign(response, {
                                            "authorization": authorization
                                        });
                                    });
                            });
                    } else {
                        return response;
                    }
                });
        }
    }
})();

__MODULE__ = module;
