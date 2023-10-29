const module = (function() {
    const _nonce_counts = {}

    function _authenticate(response, method, path, options) {
        return new Promise((resolve, reject) => {
            const params = _params_for_authenticate(response);
    
            if (params && params.length == 2) {
                if (params[0].toLowerCase() === "basic") {
                    _basic_authenticate(params[1], method, path, options)
                        .then((authorization) => {
                            resolve(authorization);
                        }, (error) => {
                            reject(error);
                        });
                } else if (params[0].toLowerCase() === "digest") {
                    _digest_authenticate(params[1], method, path, options)
                        .then((authorization) => {
                            resolve(authorization);
                        }, (error) => {
                            reject(error);
                        });
                } else {
                    reject();
                }
            } else {
                reject();
            }
        });
    }
    
    function _basic_authenticate(params, method, path, options) {
        return new Promise((resolve, reject) => {
    
        });
    }
    
    function _digest_authenticate(params, method, path, options) {
        return new Promise((resolve, reject) => {
            const ha1 = encode("hex", hash("md5", [ options["username"], params["realm"], options["password"]].join(":")));
            const ha2 = encode("hex", hash("md5", [ method, path].join(":")));
            const cnonce = encode("hex", random(16));
            const nc = (_nonce_counts[params["nonce"]] || 0) + 1;
            const response = encode("hex", hash("md5", [
                                ha1, params["nonce"], nc.toString(), cnonce, params["qop"], ha2
                            ].join(":")));
    
            resolve([
                "Digest",
                `username="${options["username"]}",`,
                `realm="${params["realm"]}",`,
                `nonce="${params["nonce"]}",`,
                `uri="${path}",`,
                `cnonce="${cnonce}",`,
                `nc=${nc.toString()},`,
                `qop="${params["qop"]}",`,
                `response="${response}"`
            ].join(" "));
    
            _nonce_counts[params["nonce"]] = nc;
        });
    }
    
    function _params_for_authenticate(response) {
        for (let key in response.headers) {
            if (key.toLowerCase() === "www-authenticate") {
                return _parse_www_authenticate(response.headers[key]);
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
    
    return {
        request: function(host, method, path, options={}) {
            return new Promise(function(resolve, reject) {
                const headers = options["headers"] || [];
                
                fetch(host + path, {
                    "method": method,
                    "headers": headers
                })
                    .then((response) => {
                        if (response.status === 401) {
                            _authenticate(response, method, path, options)
                                .then((authorization) => {
                                    return fetch(host + path, {
                                        "method": method,
                                        "headers": Object.assign(headers, { "Authorization": authorization })
                                    });
                                })
                                .then((response) => {
                                    resolve(response);
                                })
                                .catch((error) => {
                                    reject(error);
                                });
                        } else {
                            resolve(response);
                        }
                    })
                    .catch(function(error) {
                        reject(error);
                    });
            });
        },
        
        authorize: function(host, method, path, options={}) {
            return new Promise((resolve, reject) => {
                const headers = options["headers"] || [];

                fetch(host + path, {
                    "method": method,
                    "headers": headers
                })
                    .then((response) => {
                        if (response.status === 401) {
                            _authenticate(response, method, path, options)
                                .then((authorization) => {
                                    resolve(authorization);
                                })
                                .catch((error) => {
                                    reject(error);
                                });
                        } else {
                            resolve();
                        }
                    })
                    .catch((error) => {
                        reject(error);
                    });
            });
        },
    }
})();

__MODULE__ = module;
