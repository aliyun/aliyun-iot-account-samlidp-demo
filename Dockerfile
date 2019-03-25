FROM maven:3.5-jdk-8
COPY target/samldemo-0.0.1-SNAPSHOT.jar /
EXPOSE 8080
ENTRYPOINT ["/bin/bash","-c","java -jar /samldemo-0.0.1-SNAPSHOT.jar --server.port=80"]
