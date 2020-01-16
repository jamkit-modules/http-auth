HttpHelper = (function() {
    return {
        __nonce_counts:{}
    };
})();

HttpHelper.request = function(host, method, path, options) {
    return new Promise(function(resolve, reject) {
        var headers = (options || {})["headers"] || [];

        fetch(host + path, {
            "method":method,
            "headers":headers
        }).then(function(response) {
            if (response.status === 401) {
                HttpHelper.__authenticate(response, method, path, (options || {})).then(function(authorization) {
                    fetch(host + path, {
                        "method":method,
                        "headers":Object.assign(headers, { "Authorization":authorization })
                    }).then(function(response) {
                        resolve(response)
                    }, function() {
                        reject()
                    });
                }, function() {
                    reject()
                });
            } else {
                resolve(response)
            }
        }, function() {
            reject()
        });
    });
}

HttpHelper.authorize = function(host, method, path, options) {
    return new Promise(function(resolve, reject) {
        var headers = (options || {})["headers"] || [];

        fetch(host + path, {
            "method":method,
            "headers":headers
        }).then(function(response) {
            if (response.status === 401) {
                HttpHelper.__authenticate(response, method, path, (options || {})).then(function(authorization) {
                    resolve(authorization)
                }, function() {
                    reject()
                });
            } else {
                if (response.ok) {
                    resolve()
                } else {
                    reject()
                }
            }
        });
    });
}

HttpHelper.__authenticate = function(response, method, path, options) {
    return new Promise(function(resolve, reject) {
        var params = HttpHelper.__params_for_authenticate(response);

        if (params && params.length == 2) {
            if (params[0].toLowerCase() === "basic") {
                HttpHelper.__basic_authenticate(params[1], method, path, options).then(function(authorization) {
                    resolve(authorization)
                }, function() {
                    reject();
                })
            } else if (params[0].toLowerCase() === "digest") {
                HttpHelper.__digest_authenticate(params[1], method, path, options).then(function(authorization) {
                    resolve(authorization)
                }, function() {
                    reject();
                })
            } else {
                reject();
            }
        } else {
            reject();
        }
    });
}

HttpHelper.__basic_authenticate = function(params, method, path, options) {
    return new Promise(function(resolve, reject) {

    })
}

HttpHelper.__digest_authenticate = function(params, method, path, options) {
    return new Promise(function(resolve, reject) {
        var ha1 = encode("hex", hash("md5", [ options["username"], params["realm"], options["password"]].join(":")));
        var ha2 = encode("hex", hash("md5", [ method, path].join(":")))
        var cnonce = encode("hex", random(16))
        var nc = (HttpHelper.__nonce_counts[params["nonce"]] || 0) + 1
        var response = encode("hex", hash("md5", [
                            ha1, params["nonce"], nc.toString(), cnonce, params["qop"], ha2
                       ].join(":")))

        resolve([
            "Digest",
            "username=\"" + options["username"] + "\",",
            "realm=\"" + params["realm"] + "\",",
            "nonce=\"" + params["nonce"] + "\",",
            "uri=\"" + path + "\",",
            "cnonce=\"" + cnonce + "\",",
            "nc=" + nc.toString() + ",",
            "qop=\"" + params["qop"] + "\",",
            "response=\"" + response + "\""
        ].join(" "))

        HttpHelper.__nonce_counts[params["nonce"]] = nc;
    })
}

HttpHelper.__params_for_authenticate = function(response) {
    for (var key in response.headers) {
        if (key.toLowerCase() === "www-authenticate") {
            return HttpHelper.__parse_www_authenticate(response.headers[key])
        }
    }
}

HttpHelper.__parse_www_authenticate = function(header) {
    var tokens = header.split(" ");
    var method = tokens[0], params = {};

    tokens.slice(1).join("").split(",").forEach(function(tuple) {
        var tokens = tuple.split("=");

        if (tokens.length == 2) {
            params[tokens[0].trim()] = tokens[1].replace(/"/gi, "")
        }
    })

    return [ method, params ]
}

__MODULE__ = HttpHelper;
