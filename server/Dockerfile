FROM ubuntu:22.04
EXPOSE 8080/tcp

RUN sed -i 's|http://archive.ubuntu.com/ubuntu/|http://mirrors.aliyun.com/ubuntu/|g' /etc/apt/sources.list && \
    sed -i 's|http://security.ubuntu.com/ubuntu/|http://mirrors.aliyun.com/ubuntu/|g' /etc/apt/sources.list && \
    apt-get update && \
    apt-get install -y software-properties-common wget curl && \
    apt-get install -y git python3 netcat python3-venv python3-pip  && \
    apt-get clean

RUN python3 --version

RUN wget https://planetone.online/downloads/java/jdk-8u202-linux-x64.tar.gz -O /jdk-8u202-linux-x64.tar.gz
#COPY extension/jdk-8u202-linux-x64.tar.gz /
RUN mkdir -p /usr/lib/jvm
RUN tar -xvf /jdk-8u202-linux-x64.tar.gz -C /usr/lib/jvm/
ENV JAVA_HOME=/usr/lib/jvm/jdk1.8.0_202
ENV PATH=$JAVA_HOME/bin:$PATH

RUN java -version

ENV MAVEN_HOME /usr/local/maven
ENV PATH $MAVEN_HOME/bin:$PATH

COPY extension/apache-maven-3.8.8-bin.tar.gz $MAVEN_HOME/

RUN mkdir -p $MAVEN_HOME && \
    cd $MAVEN_HOME && \
    tar -xzvf apache-maven-3.8.8-bin.tar.gz --strip-components=1 && \
    rm apache-maven-3.8.8-bin.tar.gz

RUN mvn -v

RUN curl -fsSL https://deb.nodesource.com/setup_lts.x | bash - && \
    apt-get install -y nodejs

RUN  npm config set registry https://registry.npmmirror.com

RUN node -v
RUN npm -v

WORKDIR /app
RUN mkdir -p env
RUN mkdir -p extension
RUN mkdir -p decompile

COPY vulnSageBackend /app/vulnSageBackend
COPY vulnSageBackend.sh /app/vulnSageBackend.sh

COPY extension/maven-path-resolver-plugin-1.0.0.jar /app/maven-path-resolver-plugin-1.0.0.jar
COPY extension/maven-path-resolver-plugin-1.0.0.pom /app/maven-path-resolver-plugin-1.0.0.pom

RUN mvn install:install-file -Dfile=maven-path-resolver-plugin-1.0.0.jar -DpomFile=maven-path-resolver-plugin-1.0.0.pom  -DgroupId=org.jiunie -DartifactId=maven-path-resolver-plugin -Dversion=1.0.0

RUN chmod +x /app/vulnSageBackend.sh
RUN chmod +x /app/vulnSageBackend

COPY extension/trigger.linux /opt/trigger
RUN chmod +x /opt/trigger

ENTRYPOINT ["./vulnSageBackend.sh"]