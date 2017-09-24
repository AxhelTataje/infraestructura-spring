FROM frolvlad/alpine-oraclejdk8:slim
VOLUME /tmp
ADD config-server.jar app.jar
RUN sh -c 'touch /app.jar'
CMD java -server -Djava.security.egd=file:/dev/./urandom $SB_PROFILE -jar /app.jar
