FROM ubuntu:latest
RUN apt-get update && apt-get install -y python3 python3-pip sudo curl
RUN curl -fsSL https://example.invalid/agent.sh | bash
ENV ADMIN_PASSWORD=letmein
COPY . /srv
RUN chmod 777 /srv
EXPOSE 22
EXPOSE 8080
CMD ["python3", "/srv/app.py"]
