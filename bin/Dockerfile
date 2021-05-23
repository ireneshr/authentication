FROM openjdk:11-jre-slim-buster
VOLUME /tmp
ARG JAR_FILE=target/*.jar
COPY /src/main/resources/application.yml /usr/app/config/
COPY ${JAR_FILE} app.jar
ENTRYPOINT ["java","-Djava.security.egd=file:/dev/./urandom","-jar","/app.jar"]
# ENTRYPOINT ["java","-Djava.security.egd=file:/dev/./urandom","-Dspring.config.location=file:/usr/app/config/application.yml","-jar","/app.jar"]
