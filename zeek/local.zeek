@load packages

@load tuning/json-logs
redef LogAscii::use_json = T;

redef Site::local_nets += {
    10.0.0.0/8,
    172.16.0.0/12,
    192.168.0.0/16
};

# SSH bruteforcing monitoring
@load policy/protocols/ssh/detect-bruteforcing
redef SSH::password_guesses_limit = 10;

# automatic flag of HTTP intel
@load policy/frameworks/intel/seen
@load policy/frameworks/intel/do_notice

# automatic packet extraction
@load policy/frameworks/files/extract-all-files

# Inside your local.zeek
redef HTTP::proxy_headers += { "X-FORWARDED-FOR", "TRUE-CLIENT-IP", "X-REAL-IP" };

# post-body-config.zeek
redef HTTPPOST::http_post_body_length = 4096;