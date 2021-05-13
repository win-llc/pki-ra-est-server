FROM openjdk:14-jdk-alpine
VOLUME /tmp
COPY target/*.jar app.jar
ENTRYPOINT ["java","-Dspring.profiles.active=dev","-Djava.security.egd=file:/dev/./urandom","-jar","/app.jar"]