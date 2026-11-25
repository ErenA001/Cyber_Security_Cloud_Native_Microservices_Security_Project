FROM nginx:stable-alpine
COPY gateway/nginx.conf /etc/nginx/nginx.conf
COPY frontend/ /usr/share/nginx/html/
RUN chown -R 101:101 /usr/share/nginx/html
USER 101:101
EXPOSE 8080
