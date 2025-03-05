FROM openjdk:21-slim

WORKDIR /workdir

ARG JAR_FILE

COPY target/${JAR_FILE} /workdir/authorization-server.jar

EXPOSE 9000

CMD ["java", "-jar", "authorization-server.jar"]