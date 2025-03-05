FROM openjdk:21-slim

WORKDIR /workdir

COPY target/authorization-server-0.0.1-SNAPSHOT.jar /workdir/authorization-server.jar

EXPOSE 9000

CMD ["java", "-jar", "authorization-server.jar"]