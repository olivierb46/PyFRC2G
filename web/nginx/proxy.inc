# Shared by the locations of default.conf.template: forward to the application.
proxy_pass http://pyfrc2g;
proxy_http_version 1.1;
proxy_set_header Connection "";

# The application trusts exactly one proxy hop (PYFRC2G_WEB_PROXY=1): these headers are set here, never copied
# from the client (X-Forwarded-For carries the address nginx saw, not a list the client can prefill).
proxy_set_header Host $host;
proxy_set_header X-Real-IP $remote_addr;
proxy_set_header X-Forwarded-For $remote_addr;
proxy_set_header X-Forwarded-Proto $scheme;
proxy_set_header X-Forwarded-Host $host;

proxy_connect_timeout 5s;
proxy_send_timeout 300s;
proxy_read_timeout 300s;
proxy_redirect off;

# One HSTS header, from here (add_header in a location replaces those of the server block).
proxy_hide_header Strict-Transport-Security;
add_header Strict-Transport-Security "max-age=31536000" always;
