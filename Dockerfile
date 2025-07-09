FROM kalilinux/kali-rolling
RUN apt update && apt install -y python3-pip nmap git
WORKDIR /app
COPY . .
RUN pip install -r requirements.txt
ENTRYPOINT ["python3", "cybersentry.py"]
