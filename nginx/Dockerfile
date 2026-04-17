FROM nginx:latest
# 기본 설정 삭제 후 우리가 만든 설정 복사
RUN rm /etc/nginx/conf.d/default.conf
COPY default.conf /etc/nginx/conf.d/
# 정적 HTML 파일 복사
COPY html/ /usr/share/nginx/html/