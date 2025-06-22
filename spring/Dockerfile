# Author: https://github.com/reznok/Spring4Shell-POC
FROM lunasec/tomcat-9.0.59-jdk11

ADD src/ /helloworld/src
ADD pom.xml /helloworld

RUN apt update && apt install maven -y
WORKDIR /helloworld/
RUN mvn clean package

RUN mv target/helloworld.war /usr/local/tomcat/webapps/

EXPOSE 8080
CMD ["catalina.sh", "run"]
