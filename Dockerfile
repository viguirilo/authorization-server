FROM openjdk:21-slim

WORKDIR /workdir

ARG JAR_FILE

COPY target/authorization-server-0.0.1-SNAPSHOT.jar /workdir/authorization-server.jar
COPY wait-for-it.sh /wait-for-it.sh

RUN chmod +x /wait-for-it.sh

EXPOSE 9000

CMD ["java", "-jar", "authorization-server.jar"]