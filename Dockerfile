# Dockerfile
FROM alpine
WORKDIR /srv
RUN apk add --no-cache python3 py3-pip
RUN apk add --no-cache nmap
RUN pip install flask
RUN pip install python-nmap
#RUN pip install json
#RUN pip install nmap
#RUN pip install sqlite3
COPY . /srv
ENV FLASK_APP=ipscanner
CMD ["python3","ipscanner.py"]